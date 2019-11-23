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

#pragma once

#include <functional>
#include <QObject>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include "common/download.h"

namespace TriState
{
  Q_NAMESPACE
  enum tristate_t
  {
    TriUnknown,
    TriTrue,
    TriFalse
  };
  Q_ENUM_NS(tristate_t)
};

enum State
{
  StateNone,
  StateInit,
  StateQueryDNS,
  StateDNSFailed,
  StateCheckVersion,
  StateUpToDate,
  StateBackInTime,
  StateNoUpdateInfoFound,
  StateDownload,
  StateDownloadFailed,
  StateCheckHash,
  StateBadHash,
  StateValidUpdate,
};

struct dns_query_result_t
{
  bool avail;
  bool valid;
  std::vector<std::string> records;
};

class Updater: public QObject
{
  Q_OBJECT
  Q_PROPERTY(QString state READ getState NOTIFY stateChanged)
  Q_PROPERTY(QString version READ getVersion NOTIFY versionChanged)
  Q_PROPERTY(TriState::tristate_t dnsValid READ getDnsValid NOTIFY dnsValidChanged)
  Q_PROPERTY(TriState::tristate_t hashValid READ getHashValid NOTIFY hashValidChanged)

public:
  explicit Updater(QObject *parent = nullptr);
  virtual ~Updater();

  typedef TriState::tristate_t tristate_t;

  QString getState() const;
  QString getVersion() const;
  TriState::tristate_t getDnsValid() const;
  TriState::tristate_t getHashValid() const;

  Q_INVOKABLE void retryDownload();

private:
  void updater_thread();
  void set_state(State s);
  void setDnsValid(tristate_t t);
  void setHashValid(tristate_t t);

  void add_message(const std::string &s);
  void load_txt_records_from_dns(const std::vector<std::string> &dns_urls, std::vector<dns_query_result_t> &results, std::vector<std::string> &good_records);
  void process_version(const std::string &software, const std::string &buildtag, const std::vector<std::string> &records);
  void start_download();
  void check_hash();

signals:
  void stateChanged(const QString &state);
  void versionChanged(const QString &version);
  void dnsValidChanged(TriState::tristate_t dnsValid);
  void hashValidChanged(TriState::tristate_t hashValid);
  void message(const QString &s);
  void downloadProgress(quint64 downloaded, quint64 total);
  void downloadStarted();
  void downloadFinished(bool success);
  void validUpdateReady(const QString &filename);

private:
  bool running;
  mutable boost::mutex mutex;
  boost::condition_variable cond;
  boost::thread thread;

  State state;
  std::vector<dns_query_result_t> dns_query_results;
  std::vector<std::string> good_dns_records;
  std::vector<std::string> messages;

  std::string version;
  std::string expected_hash;
  TriState::tristate_t dnsValid;
  TriState::tristate_t hashValid;

  std::string software;
  std::string buildtag;
  std::string current_version;

  bool dns_query_done;
  bool version_check_done;
  bool download_done;
  bool download_success;

  boost::filesystem::path download_path;
  tools::download_async_handle download_handle;
};
