/*  monero-update - An downloaded/checker updater for Monero
 *
 *  Copyright (c) 2019, The Monero Project
 *
 *  All rights reserved.
 *  
 *  monero-update is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  monero-update is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with monero-update.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <functional>
#include <tuple>
#include <QObject>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <gpgme.h>
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
  StateFetchGitianSigs,
  StateImportPubkeys,
  StatePubkeyImportFailed,
  StateVerifyGitianSignatures,
  StateNoGitianSigs,
  StateNotEnoughGitianSigs,
  StateBadGitianSigs,
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
  Q_PROPERTY(uint32_t validGitianSigs READ getValidGitianSigs NOTIFY validGitianSigsChanged)
  Q_PROPERTY(uint32_t minValidGitianSigs READ getMinValidGitianSigs NOTIFY minValidGitianSigsChanged)
  Q_PROPERTY(uint32_t processedGitianSigs READ getProcessedGitianSigs NOTIFY processedGitianSigsChanged)
  Q_PROPERTY(uint32_t totalGitianSigs READ getTotalGitianSigs NOTIFY totalGitianSigsChanged)
  Q_PROPERTY(TriState::tristate_t stateOutcome READ getStateOutcome NOTIFY stateOutcomeChanged)

public:
  explicit Updater(QObject *parent = nullptr);
  virtual ~Updater();

  typedef TriState::tristate_t tristate_t;

  QString getState() const;
  QString getVersion() const;
  TriState::tristate_t getDnsValid() const;
  TriState::tristate_t getHashValid() const;
  uint32_t getValidGitianSigs() const;
  uint32_t getMinValidGitianSigs() const;
  uint32_t getTotalGitianSigs() const;
  uint32_t getProcessedGitianSigs() const;
  TriState::tristate_t getStateOutcome() const;

  Q_INVOKABLE void retryDownload();

private:
  void updater_thread();
  void set_state(State s);
  void setDnsValid(tristate_t t);
  void setHashValid(tristate_t t);
  void setValidGitianSigs(uint32_t sigs);
  void setMinValidGitianSigs(uint32_t sigs);
  void setTotalGitianSigs(uint32_t sigs);
  void setProcessedGitianSigs(uint32_t sigs);

  void add_message(const std::string &s);
  void load_txt_records_from_dns(const std::vector<std::string> &dns_urls, std::vector<dns_query_result_t> &results, std::vector<std::string> &good_records);
  void process_version(const std::string &software, const std::string &buildtag, const std::vector<std::string> &records);
  void start_download();
  void check_hash();
  bool init_gpgme();
  void import_pubkeys();
  void fetch_gitian_sigs();
  tristate_t verify_gitian_signature(const std::string &contents, const std::string &signature, std::string &fingerprint);

signals:
  void stateChanged(const QString &state);
  void versionChanged(const QString &version);
  void dnsValidChanged(TriState::tristate_t dnsValid);
  void hashValidChanged(TriState::tristate_t hashValid);
  void validGitianSigsChanged(uint32_t sigs);
  void minValidGitianSigsChanged(uint32_t sigs);
  void totalGitianSigsChanged(uint32_t sigs);
  void processedGitianSigsChanged(uint32_t sigs);
  void stateOutcomeChanged(TriState::tristate_t stateOutcome);
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
  uint32_t validGitianSigs;
  uint32_t minValidGitianSigs;
  uint32_t totalGitianSigs;
  uint32_t processedGitianSigs;

  std::string software;
  std::string buildtag;
  std::string current_version;

  bool dns_query_done;
  bool version_check_done;
  bool download_done;
  bool download_success;
  bool gitian_pubkeys_import_done;
  bool gitian_pubkeys_import_success;
  bool gitian_verify_sigs_done;
  bool gitian_verify_sigs_success;

  boost::filesystem::path download_path;
  tools::download_async_handle download_handle;
  boost::filesystem::path gpg_home;

  gpgme_ctx_t ctx;

  std::map<std::string, std::string> imported_fingerprints;
};
