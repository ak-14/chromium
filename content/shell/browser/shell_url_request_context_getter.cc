// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/shell/browser/shell_url_request_context_getter.h"

#include <memory>
#include <utility>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/task_scheduler/post_task.h"
#include "build/build_config.h"
#include "components/network_session_configurator/browser/network_session_configurator.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/cookie_store_factory.h"
#include "content/public/common/content_switches.h"
#include "content/shell/browser/shell_network_delegate.h"
#include "content/shell/common/layout_test/layout_test_switches.h"
#include "content/shell/common/shell_content_client.h"
#include "content/shell/common/shell_switches.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cookies/cookie_store.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/http/http_network_session.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/network_switches.h"
#include "url/url_constants.h"

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_service.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

namespace content {

namespace {

// TODO(rsleevi): Embedders should see https://crbug.com/700973 before using
// this pattern.
class IgnoresCTPolicyEnforcer : public net::CTPolicyEnforcer {
 public:
  IgnoresCTPolicyEnforcer() = default;
  ~IgnoresCTPolicyEnforcer() override = default;

  net::ct::CTPolicyCompliance CheckCompliance(
      net::X509Certificate* cert,
      const net::SCTList& verified_scts,
      const net::NetLogWithSource& net_log) override {
    return net::ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS;
  }
};

}  // namespace

ShellURLRequestContextGetter::ShellURLRequestContextGetter(
    bool ignore_certificate_errors,
    bool off_the_record,
    const base::FilePath& base_path,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    ProtocolHandlerMap* protocol_handlers,
    URLRequestInterceptorScopedVector request_interceptors,
    net::NetLog* net_log)
    : ignore_certificate_errors_(ignore_certificate_errors),
      off_the_record_(off_the_record),
      shut_down_(false),
      base_path_(base_path),
      io_task_runner_(std::move(io_task_runner)),
      net_log_(net_log),
      request_interceptors_(std::move(request_interceptors)) {
  // Must first be created on the UI thread.
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  std::swap(protocol_handlers_, *protocol_handlers);

  // We must create the proxy config service on the UI loop on Linux because it
  // must synchronously run on the glib message loop. This will be passed to
  // the URLRequestContextStorage on the IO thread in GetURLRequestContext().
  proxy_config_service_ = GetProxyConfigService();
}

ShellURLRequestContextGetter::~ShellURLRequestContextGetter() {}

void ShellURLRequestContextGetter::NotifyContextShuttingDown() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  shut_down_ = true;
  URLRequestContextGetter::NotifyContextShuttingDown();
  url_request_context_ = nullptr;  // deletes it
}

std::unique_ptr<net::NetworkDelegate>
ShellURLRequestContextGetter::CreateNetworkDelegate() {
  return base::WrapUnique(new ShellNetworkDelegate);
}

std::unique_ptr<net::CertVerifier>
ShellURLRequestContextGetter::GetCertVerifier() {
  return net::CertVerifier::CreateDefault();
}

std::unique_ptr<net::ProxyConfigService>
ShellURLRequestContextGetter::GetProxyConfigService() {
  return net::ProxyResolutionService::CreateSystemProxyConfigService(
      io_task_runner_);
}

std::unique_ptr<net::ProxyResolutionService>
ShellURLRequestContextGetter::GetProxyService() {
  // TODO(jam): use v8 if possible, look at chrome code.
  return nullptr;
}

net::URLRequestContext* ShellURLRequestContextGetter::GetURLRequestContext() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  if (shut_down_)
    return nullptr;

  if (!url_request_context_) {
    const base::CommandLine& command_line =
        *base::CommandLine::ForCurrentProcess();

    net::URLRequestContextBuilder builder;
    builder.set_net_log(net_log_);
    builder.set_network_delegate(CreateNetworkDelegate());
    std::unique_ptr<net::CookieStore> cookie_store =
        CreateCookieStore(CookieStoreConfig());
    std::unique_ptr<net::ChannelIDService> channel_id_service =
        std::make_unique<net::ChannelIDService>(
            new net::DefaultChannelIDStore(nullptr));
    cookie_store->SetChannelIDServiceID(channel_id_service->GetUniqueID());
    builder.SetCookieAndChannelIdStores(std::move(cookie_store),
                                        std::move(channel_id_service));
    builder.set_accept_language("en-us,en");
    builder.set_user_agent(GetShellUserAgent());

    builder.SetCertVerifier(GetCertVerifier());
    builder.set_ct_verifier(base::WrapUnique(new net::DoNothingCTVerifier));
    builder.set_ct_policy_enforcer(
        base::WrapUnique(new IgnoresCTPolicyEnforcer));

    std::unique_ptr<net::ProxyResolutionService> proxy_resolution_service =
        GetProxyService();
    if (proxy_resolution_service) {
      builder.set_proxy_resolution_service(std::move(proxy_resolution_service));
    } else {
      builder.set_proxy_config_service(std::move(proxy_config_service_));
    }

    net::URLRequestContextBuilder::HttpCacheParams cache_params;
    if (!off_the_record_) {
      cache_params.path = base_path_.Append(FILE_PATH_LITERAL("Cache"));
      cache_params.type = net::URLRequestContextBuilder::HttpCacheParams::DISK;
    } else {
      cache_params.type =
          net::URLRequestContextBuilder::HttpCacheParams::IN_MEMORY;
    }
    builder.EnableHttpCache(cache_params);

    net::HttpNetworkSession::Params network_session_params;
    network_session_configurator::ParseCommandLineAndFieldTrials(
        command_line, false /* is_quic_force_disabled */,
        GetShellUserAgent() /* quic_user_agent_id */, &network_session_params);
    network_session_params.ignore_certificate_errors =
        ignore_certificate_errors_;
    builder.set_http_network_session_params(network_session_params);

    if (command_line.HasSwitch(network::switches::kHostResolverRules)) {
      std::unique_ptr<net::MappedHostResolver> mapped_host_resolver(
          new net::MappedHostResolver(
              net::HostResolver::CreateDefaultResolver(net_log_)));
      mapped_host_resolver->SetRulesFromString(command_line.GetSwitchValueASCII(
          network::switches::kHostResolverRules));
      builder.set_host_resolver(std::move(mapped_host_resolver));
    }

    // Keep ProtocolHandlers added in sync with
    // ShellContentBrowserClient::IsHandledURL().

    for (auto& protocol_handler : protocol_handlers_) {
      builder.SetProtocolHandler(
          protocol_handler.first,
          base::WrapUnique(protocol_handler.second.release()));
    }
    protocol_handlers_.clear();

    builder.set_data_enabled(true);

#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
    builder.set_file_enabled(true);
#endif

    // Set up interceptors in the reverse order.
    builder.SetInterceptors(std::move(request_interceptors_));

#if BUILDFLAG(ENABLE_REPORTING)
    if (base::FeatureList::IsEnabled(network::features::kReporting)) {
      std::unique_ptr<net::ReportingPolicy> reporting_policy =
          std::make_unique<net::ReportingPolicy>();
      if (command_line.HasSwitch(switches::kRunLayoutTest))
        reporting_policy->delivery_interval =
            base::TimeDelta::FromMilliseconds(100);
      builder.set_reporting_policy(std::move(reporting_policy));
    }
#endif  // BUILDFLAG(ENABLE_REPORTING)

    builder.set_enable_brotli(true);

    url_request_context_ = builder.Build();
  }

  return url_request_context_.get();
}

scoped_refptr<base::SingleThreadTaskRunner>
    ShellURLRequestContextGetter::GetNetworkTaskRunner() const {
  return BrowserThread::GetTaskRunnerForThread(BrowserThread::IO);
}

net::HostResolver* ShellURLRequestContextGetter::host_resolver() {
  return url_request_context_->host_resolver();
}

}  // namespace content
