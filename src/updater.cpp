/*  monero-update - An downloaded/checker updater for Monero
 *
 *  Copyright (c) 2019, The Monero Project
 *
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without modification, are
 *  permitted provided that the following conditions are met:
 *  
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *  
 *  3. Neither the name of the copyright holder nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without specific
 *     prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 *  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <random>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include "common/threadpool.h"
#include "common/dns_utils.h"
#include "common/vercmp.h"
#include "common/updates.h"
#include "common/download.h"
#include "common/sha256sum.h"
#include "updater.h"

static std::string detect_build_tag(void)
{
  std::string cpuinfo;

#if defined _WIN64
  return "win-x64";
#endif

#if defined _WIN32
  return "win-x86";
#endif

#if defined __FreeBSD__ || defined __FreeBSD_kernel__
  return "freebsd";
#endif

#if defined __APPLE__
  return "mac-x64";
#endif

#if defined __linux__ && (defined __arm__ || defined __arch64__)
  if (epee::file_io_utils::load_file_to_string("/proc/cpuinfo", cpuinfo))
  {
    if (strstr(cpuinfo, "ARMv7"))
      return "linux-armv7";
    if (strstr(cpuinfo, "ARMv8"))
      return "linux-armv8";
  }
  // unknown, assume v7 for compatibility
  return "linux-armv7";
#endif

#if defined __linux__ && defined __i386__
  return "linux-x86";
#endif

#if defined __linux__ && defined __x86_64__
  return "linux-x64";
#endif
// TODO: armv8

  return "source";
}

#ifndef BUILDTAG
#define BUILDTAG "source"
#define SUBDIR "source"
#else
#define SUBDIR "cli"
#endif

#define SOFTWARE "monero"

static std::map<State, const char*> state_names = {
  std::make_pair(StateNone, "None"),
  std::make_pair(StateInit, "Initializing"),
  std::make_pair(StateQueryDNS, "Querying DNS"),
  std::make_pair(StateDNSFailed, "DNS check failed"),
  std::make_pair(StateCheckVersion, "Checking version"),
  std::make_pair(StateUpToDate, "We are up to date"),
  std::make_pair(StateBackInTime, "Only old versions found"),
  std::make_pair(StateNoUpdateInfoFound, "No update information found"),
  std::make_pair(StateDownload, "Downloading update"),
  std::make_pair(StateDownloadFailed, "Download failed"),
  std::make_pair(StateCheckHash, "Checking failed"),
  std::make_pair(StateBadHash, "Invalid hash"),
  std::make_pair(StateValidUpdate, "Valid update downloaded and verified"),
};

// All four MoneroPulse domains have DNSSEC on and valid
static const std::vector<std::string> dns_urls = {
    "updates.moneropulse.org",
    "updates.moneropulse.net",
    "updates.moneropulse.co",
    "updates.moneropulse.se"
};

static const char *get_state_name(State state)
{
  return state_names[state];
}

Updater::Updater(QObject *parent):
  QObject(parent),
  state(StateNone),
  dnsValid(TriState::TriUnknown),
  hashValid(TriState::TriUnknown),

  software(SOFTWARE),
  buildtag(detect_build_tag()),
  current_version(""),

  dns_query_done(false),
  version_check_done(false),
  download_done(false),
  download_success(false)
{
  running = true;
  thread = boost::thread([this]() { updater_thread(); } );
  set_state(StateInit);
}

Updater::~Updater()
{
  {
    boost::unique_lock<boost::mutex> lock(mutex);
    running = false;
    cond.notify_one();
  }
  thread.join();
}

void Updater::setDnsValid(tristate_t t)
{
  dnsValid = t;
  emit dnsValidChanged(dnsValid);
}

void Updater::setHashValid(tristate_t t)
{
  hashValid = t;
  emit hashValidChanged(hashValid);
}

void Updater::load_txt_records_from_dns(const std::vector<std::string> &dns_urls, std::vector<dns_query_result_t> &results, std::vector<std::string> &good_records)
{
  boost::unique_lock<boost::mutex> lock(mutex);

  dns_query_done = false;
  setDnsValid(TriState::TriUnknown);
  results.resize(dns_urls.size());
  good_records.clear();

  size_t first_index = (std::default_random_engine(time(NULL) ^ getpid())()) % dns_urls.size();

  add_message("Lookup up DNS TXT records for: " + boost::join(dns_urls, ", "));

  // send all requests in parallel
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;
  for (size_t n = 0; n < dns_urls.size(); ++n)
  {
    tpool.submit(&waiter,[n, dns_urls, &results](){
      results[n].records = tools::DNSResolver::instance().get_txt_record(dns_urls[n], results[n].avail, results[n].valid); 
    });
  }
  lock.unlock();
  waiter.wait(&tpool);
  lock.lock();

  size_t cur_index = first_index;
  do
  {
    const std::string &url = dns_urls[cur_index];
    if (!results[cur_index].avail)
    {
      add_message("DNSSEC not available for hostname: " + url + ", skipping.");
    }
    else if (!results[cur_index].valid)
    {
      add_message("DNSSEC validation failed for hostname: " + url + ", skipping.");
    }
    else if (results[cur_index].records.empty())
    {
      add_message("No records for hostname: " + url + ", skipping.");
    }

    cur_index++;
    if (cur_index == dns_urls.size())
    {
      cur_index = 0;
    }
  } while (cur_index != first_index);

  size_t num_valid_records = 0;

  for( const auto& record_set : results)
  {
    if (record_set.avail && record_set.valid && record_set.records.size() != 0)
    {
      num_valid_records++;
    }
  }

  if (num_valid_records < 2)
  {
    add_message("WARNING: no two valid DNS TXT records were received");
    setDnsValid(TriState::TriFalse);
    dns_query_done = true;
    return;
  }

  int good_records_index = -1;
  for (size_t i = 0; i < results.size() - 1; ++i)
  {
    if (!results[i].avail || !results[i].valid || results[i].records.size() == 0) continue;

    for (size_t j = i + 1; j < results.size(); ++j)
    {
      if (tools::dns_utils::dns_records_match(results[i].records, results[j].records))
      {
        good_records_index = i;
        break;
      }
    }
    if (good_records_index >= 0) break;
  }

  if (good_records_index < 0)
  {
    add_message("WARNING: no two DNS TXT records matched");
    setDnsValid(TriState::TriFalse);
    dns_query_done = true;
    return;
  }

  add_message("Found " + std::to_string(num_valid_records) + "/" + std::to_string(dns_urls.size()) + " matching DNSSEC records");
  good_records = results[good_records_index].records;
  setDnsValid(TriState::TriTrue);
  dns_query_done = true;
}

void Updater::process_version(const std::string &software, const std::string &buildtag, const std::vector<std::string> &records)
{
    boost::unique_lock<boost::mutex> lock(mutex);

    version_check_done = false;
    version = "";
    emit versionChanged("");

    bool found = false;

    std::string hash;
    for (const auto& record : records)
    {
      std::vector<std::string> fields;
      add_message("Got record: " + record);
      boost::split(fields, record, boost::is_any_of(":"));
      if (fields.size() != 4)
      {
        add_message("Updates record does not have 4 fields: " + record);
        continue;
      }

      if (software != fields[0] || buildtag != fields[1])
        continue;

      bool alnum = true;
      for (auto c: fields[3])
        if (!isalnum(c))
          alnum = false;
      if (fields[3].size() != 64 && !alnum)
      {
        add_message("Invalid hash: " + fields[3]);
        continue;
      }

      // use highest version
      if (found)
      {
        int cmp = tools::vercmp(version.c_str(), fields[2].c_str());
        if (cmp > 0)
          continue;
        if (cmp == 0 && hash != fields[3])
        {
          add_message("Two matches found for " + software + " version " + version + " on " + buildtag);
          version = "";
          version_check_done = true;
          return;
        }
      }
      version = fields[2];
      hash = fields[3];

      add_message("Found new version " + version + " with hash " + hash);
      found = true;
    }

    if (!version.empty())
    {
      expected_hash = hash;
      emit versionChanged(QString::fromStdString(version));
    }
    version_check_done = true;
}

void Updater::start_download()
{
  boost::unique_lock<boost::mutex> lock(mutex);

  const std::string subdir = strstr(buildtag.c_str(), "-source") ? "source" : strstr(software.c_str(), "-gui") ? "" : "cli";
  const std::string url = tools::get_update_url(software, subdir, buildtag, version, false);
  const std::string filename = boost::filesystem::path(url).filename().string();
  download_path = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("%%%%-%%%%-%%%%-%%%%-" + filename);
  download_done = false;
  download_success = false;

  add_message("Downloading " + url + " to " + download_path.string());

  auto on_result = [this](const std::string &path, const std::string &url, bool success)
  {
    add_message(std::string("Download finished: ") + (success ? "success" : "failed"));
    download_done = true;
    download_success = success;
    emit downloadFinished(success);
  };

  auto on_progress = [this](const std::string &path, const std::string &uri, size_t length, ssize_t content_length)
  {
    emit downloadProgress(length, content_length);
    return true;
  };

  download_handle = tools::download_async(download_path.string(), url, on_result, on_progress);
  emit downloadStarted();
}

void Updater::retryDownload()
{
  if (state == StateDownloadFailed)
    set_state(StateDownload);
}

void Updater::check_hash()
{
  std::string path;
  {
    boost::unique_lock<boost::mutex> lock(mutex);
    setHashValid(TriState::TriUnknown);
    path = download_path.string();
  }

  uint8_t file_hash[32];
  bool res = tools::sha256sum(download_path.string(), file_hash);

  boost::unique_lock<boost::mutex> lock(mutex);

  if (!res)
  {
    add_message("Error calculating file hash");
    setHashValid(TriState::TriFalse);
    return;
  }
  std::string file_hash_as_text;
  file_hash_as_text.resize(64);
  static const char digits[] = "0123456789abcdef";
  for (int i = 0; i < 32; ++i)
  {
    file_hash_as_text[i * 2] = digits[file_hash[i] >> 4];
    file_hash_as_text[i * 2 + 1] = digits[file_hash[i] & 0xf];
  }
  if (file_hash_as_text != expected_hash)
  {
    add_message("Invalid file hash");
    setHashValid(TriState::TriFalse);
    return;
  }
  add_message("Update verified, hash " + file_hash_as_text);
  emit validUpdateReady(QString::fromStdString(download_path.string()));
  setHashValid(TriState::TriTrue);
}

void Updater::add_message(const std::string &s)
{
  messages.push_back(s);
  emit message(QString::fromStdString(s));
}

void Updater::updater_thread()
{
  while (1)
  {
    {
      boost::unique_lock<boost::mutex> lock(mutex);
      if (!running)
        break;
    }

    sleep(1);

    switch (state)
    {
    case StateInit:
      set_state(StateQueryDNS);
      break;
    case StateQueryDNS:
      if (!dns_query_done)
        break;
      if (good_dns_records.empty())
        set_state(StateDNSFailed);
      else
        set_state(StateCheckVersion);
      break;
    case StateCheckVersion:
      if (!version_check_done)
        break;
      if (version.empty())
        set_state(StateNoUpdateInfoFound);
      else
      {
        int cmp = tools::vercmp(version.c_str(), current_version.c_str());
        if (cmp > 0)
          set_state(StateDownload);
        else if (cmp < 0)
          set_state(StateBackInTime);
        else
          set_state(StateUpToDate);
      }
      break;
    case StateDownload:
      if (!download_done)
        break;
      if (download_success)
        set_state(StateCheckHash);
      else
        set_state(StateDownloadFailed);
      break;
    case StateCheckHash:
      if (hashValid == TriState::TriTrue)
        set_state(StateValidUpdate);
      else if (hashValid == TriState::TriFalse)
        set_state(StateBadHash);
    default:
      break;
    }
  }
}

void Updater::set_state(State s)
{
  {
    boost::unique_lock<boost::mutex> lock(mutex);
    state = s;
  }
  switch (state)
  {
    case StateInit:
      dns_query_done = false;
      version_check_done = false;
      setDnsValid(TriState::TriUnknown);
      setHashValid(TriState::TriUnknown);
      break;
    case StateQueryDNS:
      load_txt_records_from_dns(dns_urls, dns_query_results, good_dns_records);
      break;
    case StateCheckVersion:
      process_version(software, buildtag, good_dns_records);
      break;
    case StateDownload:
      start_download();
      break;
    case StateCheckHash:
      check_hash();
      break;
    default:
      break;
  }
  emit stateChanged(get_state_name(state));
}

QString Updater::getState() const
{
  boost::unique_lock<boost::mutex> lock(mutex);
  return get_state_name(state);
}

QString Updater::getVersion() const
{
  boost::unique_lock<boost::mutex> lock(mutex);
  return QString::fromStdString(version);
}

Updater::tristate_t Updater::getDnsValid() const
{
  boost::unique_lock<boost::mutex> lock(mutex);
  return dnsValid;
}

Updater::tristate_t Updater::getHashValid() const
{
  boost::unique_lock<boost::mutex> lock(mutex);
  return hashValid;
}
