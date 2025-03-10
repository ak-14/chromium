// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_COOKIES_COOKIE_STORE_UNITTEST_H_
#define NET_COOKIES_COOKIE_STORE_UNITTEST_H_

#include <stdint.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/bind.h"
#include "base/location.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_tokenizer.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/cookies/cookie_store_test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

#if defined(OS_IOS)
#include "base/ios/ios_util.h"
#endif

// This file declares unittest templates that can be used to test common
// behavior of any CookieStore implementation.
// See cookie_monster_unittest.cc for an example of an implementation.

namespace net {

using base::Thread;
using CookieDeletionInfo = CookieStore::CookieDeletionInfo;

const int kTimeout = 1000;

const char kValidCookieLine[] = "A=B; path=/";

// The CookieStoreTestTraits must have the following members:
// struct CookieStoreTestTraits {
//   // Factory function. Will be called at most once per test.
//   static std::unique_ptr<CookieStore> Create();
//
//   // Drains the run loop(s) used to deliver cookie change notifications.
//   static void DeliverChangeNotifications();
//
//   // The cookie store supports cookies with the exclude_httponly() option.
//   static const bool supports_http_only;
//
//   // The cookie store is able to make the difference between the ".com"
//   // and the "com" domains.
//   static const bool supports_non_dotted_domains;
//
//   // The cookie store does not fold domains with trailing dots (so "com." and
//   "com" are different domains).
//   static const bool preserves_trailing_dots;
//
//   // The cookie store rejects cookies for invalid schemes such as ftp.
//   static const bool filters_schemes;
//
//   // The cookie store has a bug happening when a path is a substring of
//   // another.
//   static const bool has_path_prefix_bug;
//
//   // The cookie store forbids setting a cookie with an empty name.
//   static const bool forbids_setting_empty_name;
//
//   // The cookie store supports global tracking of cookie changes (i.e.
//   // calls to CookieStore::AddCallbackForAllChanges()).
//   static const bool supports_global_cookie_tracking;
//
//   // The cookie store supports tracking of cookie changes for an URL (i.e.
//   // calls to CookieStore::AddCallbackForUrl()).
//   static const bool supports_url_cookie_tracking;
//
//   // The cookie store supports tracking of named cookie changes (i.e.
//   // calls to CookieStore::AddCallbackForCookie()).
//   static const bool supports_named_cookie_tracking;
//
//   // The cookie store supports more than one callback per cookie change type.
//   static const bool supports_multiple_tracking_callbacks;
//
//   // The cookie store correctly distinguishes between OVERWRITE and EXPLICIT
//   // (deletion) change causes.
//   static const bool has_exact_change_cause;
//
//   // The cookie store is guaranteed to deliver cookie changes in the order
//   // in which calls were issued. This only applies to changes coming from
//   // _different_ calls. If a call results in a cookie overwrite, the deletion
//   // change must still be issued before the insertion change.
//   static const bool has_exact_change_ordering;
//
//   // Time to wait between two cookie insertions to ensure that cookies have
//   // different creation times.
//   static const int creation_time_granularity_in_ms;
// };

template <class CookieStoreTestTraits>
class CookieStoreTest : public testing::Test {
 protected:
  CookieStoreTest()
      : http_www_foo_("http://www.foo.com"),
        https_www_foo_("https://www.foo.com"),
        ftp_foo_("ftp://ftp.foo.com/"),
        ws_www_foo_("ws://www.foo.com"),
        wss_www_foo_("wss://www.foo.com"),
        www_foo_foo_("http://www.foo.com/foo"),
        www_foo_bar_("http://www.foo.com/bar"),
        http_baz_com_("http://baz.com"),
        http_bar_com_("http://bar.com") {
    // This test may be used outside of the net test suite, and thus may not
    // have a message loop.
    if (!base::MessageLoop::current())
      message_loop_.reset(new base::MessageLoop);
    weak_factory_.reset(new base::WeakPtrFactory<base::MessageLoop>(
        base::MessageLoop::current()));
  }

  // Helper methods for the asynchronous Cookie Store API that call the
  // asynchronous method and then pump the loop until the callback is invoked,
  // finally returning the value.

  std::string GetCookies(CookieStore* cs, const GURL& url) {
    DCHECK(cs);
    CookieOptions options;
    if (!CookieStoreTestTraits::supports_http_only)
      options.set_include_httponly();
    return GetCookiesWithOptions(cs, url, options);
  }

  std::string GetCookiesWithOptions(CookieStore* cs,
                                    const GURL& url,
                                    const CookieOptions& options) {
    DCHECK(cs);
    GetCookieListCallback callback;
    cs->GetCookieListWithOptionsAsync(
        url, options,
        base::Bind(&GetCookieListCallback::Run, base::Unretained(&callback)));
    callback.WaitUntilDone();
    return CanonicalCookie::BuildCookieLine(callback.cookies());
  }

  CookieList GetCookieListWithOptions(CookieStore* cs,
                                      const GURL& url,
                                      const CookieOptions& options) {
    DCHECK(cs);
    GetCookieListCallback callback;
    cs->GetCookieListWithOptionsAsync(
        url, options,
        base::Bind(&GetCookieListCallback::Run, base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.cookies();
  }

  CookieList GetAllCookiesForURL(CookieStore* cs, const GURL& url) {
    DCHECK(cs);
    GetCookieListCallback callback;
    cs->GetAllCookiesForURLAsync(url, base::Bind(&GetCookieListCallback::Run,
                                                 base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.cookies();
  }

  CookieList GetAllCookies(CookieStore* cs) {
    DCHECK(cs);
    GetCookieListCallback callback;
    cs->GetAllCookiesAsync(
        base::Bind(&GetCookieListCallback::Run, base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.cookies();
  }

  bool SetCookieWithOptions(CookieStore* cs,
                            const GURL& url,
                            const std::string& cookie_line,
                            const CookieOptions& options) {
    DCHECK(cs);
    ResultSavingCookieCallback<bool> callback;
    cs->SetCookieWithOptionsAsync(
        url, cookie_line, options,
        base::Bind(
            &ResultSavingCookieCallback<bool>::Run,
            base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  bool SetCanonicalCookie(CookieStore* cs,
                          std::unique_ptr<CanonicalCookie> cookie,
                          bool secure_source,
                          bool can_modify_httponly) {
    DCHECK(cs);
    ResultSavingCookieCallback<bool> callback;
    cs->SetCanonicalCookieAsync(
        std::move(cookie), secure_source, can_modify_httponly,
        base::Bind(&ResultSavingCookieCallback<bool>::Run,
                   base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  bool SetCookieWithServerTime(CookieStore* cs,
                               const GURL& url,
                               const std::string& cookie_line,
                               const base::Time& server_time) {
    CookieOptions options;
    if (!CookieStoreTestTraits::supports_http_only)
      options.set_include_httponly();
    options.set_server_time(server_time);
    return SetCookieWithOptions(cs, url, cookie_line, options);
  }

  bool SetCookie(CookieStore* cs,
                 const GURL& url,
                 const std::string& cookie_line) {
    CookieOptions options;
    if (!CookieStoreTestTraits::supports_http_only)
      options.set_include_httponly();
    return SetCookieWithOptions(cs, url, cookie_line, options);
  }

  void DeleteCookie(CookieStore* cs,
                    const GURL& url,
                    const std::string& cookie_name) {
    DCHECK(cs);
    NoResultCookieCallback callback;
    cs->DeleteCookieAsync(
        url, cookie_name,
        base::Bind(&NoResultCookieCallback::Run, base::Unretained(&callback)));
    callback.WaitUntilDone();
  }

  uint32_t DeleteCanonicalCookie(CookieStore* cs,
                                 const CanonicalCookie& cookie) {
    DCHECK(cs);
    ResultSavingCookieCallback<uint32_t> callback;
    cs->DeleteCanonicalCookieAsync(
        cookie, base::Bind(&ResultSavingCookieCallback<uint32_t>::Run,
                           base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteCreatedInTimeRange(
      CookieStore* cs,
      const CookieStore::TimeRange& creation_range) {
    DCHECK(cs);
    ResultSavingCookieCallback<uint32_t> callback;
    cs->DeleteAllCreatedInTimeRangeAsync(
        creation_range,
        base::BindRepeating(&ResultSavingCookieCallback<uint32_t>::Run,
                            base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteAllCreatedInTimeRange(CookieStore* cs,
                                       CookieDeletionInfo delete_info) {
    DCHECK(cs);
    ResultSavingCookieCallback<uint32_t> callback;
    cs->DeleteAllMatchingInfoAsync(
        std::move(delete_info),
        base::Bind(&ResultSavingCookieCallback<uint32_t>::Run,
                   base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteSessionCookies(CookieStore* cs) {
    DCHECK(cs);
    ResultSavingCookieCallback<uint32_t> callback;
    cs->DeleteSessionCookiesAsync(
        base::Bind(&ResultSavingCookieCallback<uint32_t>::Run,
                   base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteAll(CookieStore* cs) {
    DCHECK(cs);
    ResultSavingCookieCallback<uint32_t> callback;
    cs->DeleteAllAsync(base::Bind(&ResultSavingCookieCallback<uint32_t>::Run,
                                  base::Unretained(&callback)));
    callback.WaitUntilDone();
    return callback.result();
  }

  bool FindAndDeleteCookie(CookieStore* cs,
                           const std::string& domain,
                           const std::string& name) {
    for (auto& cookie : this->GetAllCookies(cs)) {
      if (cookie.Domain() == domain && cookie.Name() == name)
        return this->DeleteCanonicalCookie(cs, cookie);
    }

    return false;
  }

  // Returns the CookieStore for the test - each test only uses one CookieStore.
  CookieStore* GetCookieStore() {
    if (!cookie_store_)
      cookie_store_ = CookieStoreTestTraits::Create();
    return cookie_store_.get();
  }

  // Compares two cookie lines.
  void MatchCookieLines(const std::string& line1, const std::string& line2) {
    EXPECT_EQ(TokenizeCookieLine(line1), TokenizeCookieLine(line2));
  }

  // Check the cookie line by polling until equality or a timeout is reached.
  void MatchCookieLineWithTimeout(CookieStore* cs,
                                  const GURL& url,
                                  const std::string& line) {
    std::string cookies = GetCookies(cs, url);
    bool matched = (TokenizeCookieLine(line) == TokenizeCookieLine(cookies));
    base::Time polling_end_date = base::Time::Now() +
        base::TimeDelta::FromMilliseconds(
            CookieStoreTestTraits::creation_time_granularity_in_ms);

    while (!matched &&  base::Time::Now() <= polling_end_date) {
      base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(10));
      cookies = GetCookies(cs, url);
      matched = (TokenizeCookieLine(line) == TokenizeCookieLine(cookies));
    }

    EXPECT_TRUE(matched) << "\"" << cookies
                         << "\" does not match \"" << line << "\"";
  }

  const CookieURLHelper http_www_foo_;
  const CookieURLHelper https_www_foo_;
  const CookieURLHelper ftp_foo_;
  const CookieURLHelper ws_www_foo_;
  const CookieURLHelper wss_www_foo_;
  const CookieURLHelper www_foo_foo_;
  const CookieURLHelper www_foo_bar_;
  const CookieURLHelper http_baz_com_;
  const CookieURLHelper http_bar_com_;

  std::unique_ptr<base::WeakPtrFactory<base::MessageLoop>> weak_factory_;
  std::unique_ptr<base::MessageLoop> message_loop_;

 private:
  // Returns a set of strings of type "name=value". Fails in case of duplicate.
  std::set<std::string> TokenizeCookieLine(const std::string& line) {
    std::set<std::string> tokens;
    base::StringTokenizer tokenizer(line, " ;");
    while (tokenizer.GetNext())
      EXPECT_TRUE(tokens.insert(tokenizer.token()).second);
    return tokens;
  }

  std::unique_ptr<CookieStore> cookie_store_;
};
TYPED_TEST_CASE_P(CookieStoreTest);

TYPED_TEST_P(CookieStoreTest, FilterTest) {
  CookieStore* cs = this->GetCookieStore();

  base::Time two_hours_ago = base::Time::Now() - base::TimeDelta::FromHours(2);
  base::Time one_hour_ago = base::Time::Now() - base::TimeDelta::FromHours(1);
  base::Time one_hour_from_now =
      base::Time::Now() + base::TimeDelta::FromHours(1);

  std::unique_ptr<CanonicalCookie> cc(CanonicalCookie::CreateSanitizedCookie(
      this->www_foo_foo_.url(), "A", "B", std::string(), "/foo", one_hour_ago,
      one_hour_from_now, base::Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  ASSERT_TRUE(cc);
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs, std::move(cc), true /*secure_source*/, true /*modify_httponly*/));

  // Note that for the creation time to be set exactly, without modification,
  // it must be different from the one set by the line above.
  cc = CanonicalCookie::CreateSanitizedCookie(
      this->www_foo_bar_.url(), "C", "D", this->www_foo_bar_.domain(), "/bar",
      two_hours_ago, base::Time(), one_hour_ago, false, true,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT);
  ASSERT_TRUE(cc);
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs, std::move(cc), true /*secure_source*/, true /*modify_httponly*/));

  // Because of strict secure cookies, it should not be possible to create
  // a secure cookie with an HTTP URL.

  cc = CanonicalCookie::CreateSanitizedCookie(
      this->http_www_foo_.url(), "E", "F", std::string(), std::string(),
      base::Time(), base::Time(), base::Time(), true, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT);
  ASSERT_FALSE(cc);

  cc = CanonicalCookie::CreateSanitizedCookie(
      this->https_www_foo_.url(), "E", "F", std::string(), std::string(),
      base::Time(), base::Time(), base::Time(), true, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT);
  ASSERT_TRUE(cc);
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs, std::move(cc), true /*secure_source*/, true /*modify_httponly*/));

  // Get all the cookies for a given URL, regardless of properties. This 'get()'
  // operation shouldn't update the access time, as the test checks that the
  // access time is set properly upon creation. Updating the access time would
  // make that difficult.
  CookieOptions options;
  options.set_include_httponly();
  options.set_same_site_cookie_mode(
      CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
  options.set_do_not_update_access_time();

  CookieList cookies =
      this->GetCookieListWithOptions(cs, this->www_foo_foo_.url(), options);
  CookieList::iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());
  EXPECT_EQ(this->www_foo_foo_.host(), it->Domain());
  EXPECT_EQ("/foo", it->Path());
  EXPECT_EQ(one_hour_ago, it->CreationDate());
  EXPECT_TRUE(it->IsPersistent());
  // Expect expiration date is in the right range.  Some cookie implementations
  // may not record it with millisecond accuracy.
  EXPECT_LE((one_hour_from_now - it->ExpiryDate()).magnitude().InSeconds(), 5);
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(one_hour_ago, it->LastAccessDate());
  EXPECT_FALSE(it->IsSecure());
  EXPECT_FALSE(it->IsHttpOnly());

  ASSERT_TRUE(++it == cookies.end());

  // Verify that the cookie was set as 'httponly' by passing in a CookieOptions
  // that excludes them and getting an empty result.
  if (TypeParam::supports_http_only) {
    cookies = this->GetCookieListWithOptions(cs, this->www_foo_bar_.url(),
                                             CookieOptions());
    it = cookies.begin();
    ASSERT_TRUE(it == cookies.end());
  }

  // Get the cookie using the wide open |options|:
  cookies =
      this->GetCookieListWithOptions(cs, this->www_foo_bar_.url(), options);
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("D", it->Value());
  EXPECT_EQ(this->www_foo_bar_.Format(".%D"), it->Domain());
  EXPECT_EQ("/bar", it->Path());
  EXPECT_EQ(two_hours_ago, it->CreationDate());
  EXPECT_FALSE(it->IsPersistent());
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(one_hour_ago, it->LastAccessDate());
  EXPECT_FALSE(it->IsSecure());
  EXPECT_TRUE(it->IsHttpOnly());

  EXPECT_TRUE(++it == cookies.end());

  cookies =
      this->GetCookieListWithOptions(cs, this->https_www_foo_.url(), options);
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("F", it->Value());
  EXPECT_EQ("/", it->Path());
  EXPECT_EQ(this->https_www_foo_.host(), it->Domain());
  // Cookie should have its creation time set, and be in a reasonable range.
  EXPECT_LE((base::Time::Now() - it->CreationDate()).magnitude().InMinutes(),
            2);
  EXPECT_FALSE(it->IsPersistent());
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(it->CreationDate(), it->LastAccessDate());
  EXPECT_TRUE(it->IsSecure());
  EXPECT_FALSE(it->IsHttpOnly());

  EXPECT_TRUE(++it == cookies.end());
}

TYPED_TEST_P(CookieStoreTest, SetCanonicalCookieTest) {
  CookieStore* cs = this->GetCookieStore();

  base::Time two_hours_ago = base::Time::Now() - base::TimeDelta::FromHours(2);
  base::Time one_hour_ago = base::Time::Now() - base::TimeDelta::FromHours(1);
  base::Time one_hour_from_now =
      base::Time::Now() + base::TimeDelta::FromHours(1);

  std::string foo_foo_host(this->www_foo_foo_.url().host());
  std::string foo_bar_domain(this->www_foo_bar_.domain());
  std::string http_foo_host(this->http_www_foo_.url().host());
  std::string https_foo_host(this->https_www_foo_.url().host());

  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "A", "B", foo_foo_host, "/foo", one_hour_ago, one_hour_from_now,
          base::Time(), false /* secure */, false /* httponly */,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
      false /* secure_source */, true));
  // Note that for the creation time to be set exactly, without modification,
  // it must be different from the one set by the line above.
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "C", "D", "." + foo_bar_domain, "/bar", two_hours_ago, base::Time(),
          one_hour_ago, false, true, CookieSameSite::DEFAULT_MODE,
          COOKIE_PRIORITY_DEFAULT),
      false /* secure_source */, true));

  // A secure source is required for creating secure cookies.
  EXPECT_FALSE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "E", "F", http_foo_host, "/", base::Time(), base::Time(),
          base::Time(), true, false, CookieSameSite::DEFAULT_MODE,
          COOKIE_PRIORITY_DEFAULT),
      false /* secure_source */, true));

  // A secure source is also required for overwriting secure cookies.  Writing
  // a secure cookie then overwriting it from a non-secure source should fail.
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "E", "F", http_foo_host, "/", base::Time(), base::Time(),
          base::Time(), true /* secure */, false /* httponly */,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
      true /* secure_source */, true /* modify_http_only */));

  EXPECT_FALSE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "E", "F", http_foo_host, "/", base::Time(), base::Time(),
          base::Time(), true /* secure */, false /* httponly */,
          CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
      false /* secure_source */, true /* modify_http_only */));

  if (TypeParam::supports_http_only) {
    // Permission to modify http only cookies is required to create an
    // httponly cookie.
    EXPECT_FALSE(this->SetCanonicalCookie(
        cs,
        std::make_unique<CanonicalCookie>(
            "G", "H", http_foo_host, "/unique", base::Time(), base::Time(),
            base::Time(), false /* secure */, true /* httponly */,
            CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
        false /* secure_source */, false /* modify_http_only */));

    // Permission to modify httponly cookies is also required to overwrite
    // an httponly cookie.
    EXPECT_TRUE(this->SetCanonicalCookie(
        cs,
        std::make_unique<CanonicalCookie>(
            "G", "H", http_foo_host, "/unique", base::Time(), base::Time(),
            base::Time(), false /* secure */, true /* httponly */,
            CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
        false /* secure_source */, true /* modify_http_only */));

    EXPECT_FALSE(this->SetCanonicalCookie(
        cs,
        std::make_unique<CanonicalCookie>(
            "G", "H", http_foo_host, "/unique", base::Time(), base::Time(),
            base::Time(), false /* secure */, true /* httponly */,
            CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
        false /* secure_source */, false /* modify_http_only */));
  } else {
    // Leave store in same state as if the above tests had been run.
    EXPECT_TRUE(this->SetCanonicalCookie(
        cs,
        std::make_unique<CanonicalCookie>(
            "G", "H", http_foo_host, "/unique", base::Time(), base::Time(),
            base::Time(), false /* secure */, true /* httponly */,
            CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT),
        false /* secure_source */, true /* modify_http_only */));
  }

  // Get all the cookies for a given URL, regardless of properties. This 'get()'
  // operation shouldn't update the access time, as the test checks that the
  // access time is set properly upon creation. Updating the access time would
  // make that difficult.
  CookieOptions options;
  options.set_include_httponly();
  options.set_same_site_cookie_mode(
      CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
  options.set_do_not_update_access_time();

  CookieList cookies =
      this->GetCookieListWithOptions(cs, this->www_foo_foo_.url(), options);
  CookieList::iterator it = cookies.begin();

  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());
  EXPECT_EQ(this->www_foo_foo_.host(), it->Domain());
  EXPECT_EQ("/foo", it->Path());
  EXPECT_EQ(one_hour_ago, it->CreationDate());
  EXPECT_TRUE(it->IsPersistent());
  // Expect expiration date is in the right range.  Some cookie implementations
  // may not record it with millisecond accuracy.
  EXPECT_LE((one_hour_from_now - it->ExpiryDate()).magnitude().InSeconds(), 5);
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(one_hour_ago, it->LastAccessDate());
  EXPECT_FALSE(it->IsSecure());
  EXPECT_FALSE(it->IsHttpOnly());

  // Get the cookie using the wide open |options|:
  cookies =
      this->GetCookieListWithOptions(cs, this->www_foo_bar_.url(), options);
  ASSERT_EQ(1u, cookies.size());
  it = cookies.begin();

  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("D", it->Value());
  EXPECT_EQ(this->www_foo_bar_.Format(".%D"), it->Domain());
  EXPECT_EQ("/bar", it->Path());
  EXPECT_EQ(two_hours_ago, it->CreationDate());
  EXPECT_FALSE(it->IsPersistent());
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(one_hour_ago, it->LastAccessDate());
  EXPECT_FALSE(it->IsSecure());
  EXPECT_TRUE(it->IsHttpOnly());

  cookies =
      this->GetCookieListWithOptions(cs, this->https_www_foo_.url(), options);
  ASSERT_EQ(1u, cookies.size());
  it = cookies.begin();

  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("F", it->Value());
  EXPECT_EQ("/", it->Path());
  EXPECT_EQ(this->https_www_foo_.host(), it->Domain());
  // Cookie should have its creation time set, and be in a reasonable range.
  EXPECT_LE((base::Time::Now() - it->CreationDate()).magnitude().InMinutes(),
            2);
  EXPECT_FALSE(it->IsPersistent());
  // Some CookieStores don't store last access date.
  if (!it->LastAccessDate().is_null())
    EXPECT_EQ(it->CreationDate(), it->LastAccessDate());
  EXPECT_TRUE(it->IsSecure());
  EXPECT_FALSE(it->IsHttpOnly());
}

// Test enforcement around setting secure cookies.
TYPED_TEST_P(CookieStoreTest, SecureEnforcement) {
  CookieStore* cs = this->GetCookieStore();
  GURL http_url(this->http_www_foo_.url());
  std::string http_domain(http_url.host());
  GURL https_url(this->https_www_foo_.url());
  std::string https_domain(https_url.host());

  // Confirm that setting the secure attribute from an insecure source fails,
  // but the other combinations work.
  EXPECT_FALSE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "A", "B", http_domain, "/", base::Time::Now(), base::Time(),
          base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
          COOKIE_PRIORITY_DEFAULT),
      false /*secure_source*/, true /*modify_httponly*/));
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "A", "B", http_domain, "/", base::Time::Now(), base::Time(),
          base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
          COOKIE_PRIORITY_DEFAULT),
      true /*secure_source*/, true /*modify_httponly*/));
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "A", "B", http_domain, "/", base::Time::Now(), base::Time(),
          base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
          COOKIE_PRIORITY_DEFAULT),
      true /*secure_source*/, true /*modify_httponly*/));
  EXPECT_TRUE(this->SetCanonicalCookie(
      cs,
      std::make_unique<CanonicalCookie>(
          "A", "B", http_domain, "/", base::Time::Now(), base::Time(),
          base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
          COOKIE_PRIORITY_DEFAULT),
      false /*secure_source*/, true /*modify_httponly*/));
}

// The iOS networking stack uses the iOS cookie parser, which we do not
// control. While it is spec-compliant, that does not match the practical
// behavior of most UAs in some cases, which we try to replicate. See
// https://crbug.com/638389 for more information.
TYPED_TEST_P(CookieStoreTest, EmptyKeyTest) {
#if !defined(OS_IOS)
  CookieStore* cs = this->GetCookieStore();

  GURL url1("http://foo1.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url1, "foo"));
  EXPECT_EQ("foo", this->GetCookies(cs, url1));

  // Regression tests for https://crbug.com/601786
  GURL url2("http://foo2.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url2, "foo"));
  EXPECT_TRUE(this->SetCookie(cs, url2, "\t"));
  EXPECT_EQ("", this->GetCookies(cs, url2));

  GURL url3("http://foo3.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url3, "foo"));
  EXPECT_TRUE(this->SetCookie(cs, url3, "="));
  EXPECT_EQ("", this->GetCookies(cs, url3));

  GURL url4("http://foo4.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url4, "foo"));
  EXPECT_TRUE(this->SetCookie(cs, url4, ""));
  EXPECT_EQ("", this->GetCookies(cs, url4));

  GURL url5("http://foo5.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url5, "foo"));
  EXPECT_TRUE(this->SetCookie(cs, url5, "; bar"));
  EXPECT_EQ("", this->GetCookies(cs, url5));

  GURL url6("http://foo6.bar.com");
  EXPECT_TRUE(this->SetCookie(cs, url6, "foo"));
  EXPECT_TRUE(this->SetCookie(cs, url6, " "));
  EXPECT_EQ("", this->GetCookies(cs, url6));
#endif
}

TYPED_TEST_P(CookieStoreTest, DomainTest) {
  CookieStore* cs = this->GetCookieStore();
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B"));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              this->http_www_foo_.Format("C=D; domain=.%D")));
  this->MatchCookieLines("A=B; C=D",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Verify that A=B was set as a host cookie rather than a domain
  // cookie -- should not be accessible from a sub sub-domain.
  this->MatchCookieLines(
      "C=D", this->GetCookies(
                 cs, GURL(this->http_www_foo_.Format("http://foo.www.%D"))));

  // Test and make sure we find domain cookies on the same domain.
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(),
                      this->http_www_foo_.Format("E=F; domain=.www.%D")));
  this->MatchCookieLines("A=B; C=D; E=F",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Test setting a domain= that doesn't start w/ a dot, should
  // treat it as a domain cookie, as if there was a pre-pended dot.
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(),
                      this->http_www_foo_.Format("G=H; domain=www.%D")));
  this->MatchCookieLines("A=B; C=D; E=F; G=H",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Test domain enforcement, should fail on a sub-domain or something too deep.
  EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(),
                               this->http_www_foo_.Format("I=J; domain=.%R")));
  this->MatchCookieLines(
      std::string(),
      this->GetCookies(cs, GURL(this->http_www_foo_.Format("http://a.%R"))));
  EXPECT_FALSE(
      this->SetCookie(cs, this->http_www_foo_.url(),
                      this->http_www_foo_.Format("K=L; domain=.bla.www.%D")));
  this->MatchCookieLines(
      "C=D; E=F; G=H",
      this->GetCookies(cs,
                       GURL(this->http_www_foo_.Format("http://bla.www.%D"))));
  this->MatchCookieLines("A=B; C=D; E=F; G=H",
                         this->GetCookies(cs, this->http_www_foo_.url()));
}

// FireFox recognizes domains containing trailing periods as valid.
// IE and Safari do not. Assert the expected policy here.
TYPED_TEST_P(CookieStoreTest, DomainWithTrailingDotTest) {
  CookieStore* cs = this->GetCookieStore();
  if (TypeParam::preserves_trailing_dots) {
    EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(),
                                 "a=1; domain=.www.foo.com."));
    EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(),
                                 "b=2; domain=.www.foo.com.."));
    this->MatchCookieLines(std::string(),
                           this->GetCookies(cs, this->http_www_foo_.url()));
  } else {
    EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                                "a=1; domain=.www.foo.com."));
    EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(),
                                 "b=2; domain=.www.foo.com.."));
    this->MatchCookieLines("a=1",
                           this->GetCookies(cs, this->http_www_foo_.url()));
  }
}

// Test that cookies can bet set on higher level domains.
TYPED_TEST_P(CookieStoreTest, ValidSubdomainTest) {
  CookieStore* cs = this->GetCookieStore();
  GURL url_abcd("http://a.b.c.d.com");
  GURL url_bcd("http://b.c.d.com");
  GURL url_cd("http://c.d.com");
  GURL url_d("http://d.com");

  EXPECT_TRUE(this->SetCookie(cs, url_abcd, "a=1; domain=.a.b.c.d.com"));
  EXPECT_TRUE(this->SetCookie(cs, url_abcd, "b=2; domain=.b.c.d.com"));
  EXPECT_TRUE(this->SetCookie(cs, url_abcd, "c=3; domain=.c.d.com"));
  EXPECT_TRUE(this->SetCookie(cs, url_abcd, "d=4; domain=.d.com"));

  this->MatchCookieLines("a=1; b=2; c=3; d=4", this->GetCookies(cs, url_abcd));
  this->MatchCookieLines("b=2; c=3; d=4", this->GetCookies(cs, url_bcd));
  this->MatchCookieLines("c=3; d=4", this->GetCookies(cs, url_cd));
  this->MatchCookieLines("d=4", this->GetCookies(cs, url_d));

  // Check that the same cookie can exist on different sub-domains.
  EXPECT_TRUE(this->SetCookie(cs, url_bcd, "X=bcd; domain=.b.c.d.com"));
  EXPECT_TRUE(this->SetCookie(cs, url_bcd, "X=cd; domain=.c.d.com"));
  this->MatchCookieLines("b=2; c=3; d=4; X=bcd; X=cd",
                         this->GetCookies(cs, url_bcd));
  this->MatchCookieLines("c=3; d=4; X=cd", this->GetCookies(cs, url_cd));
}

// Test that setting a cookie which specifies an invalid domain has
// no side-effect. An invalid domain in this context is one which does
// not match the originating domain.
TYPED_TEST_P(CookieStoreTest, InvalidDomainTest) {
  CookieStore* cs = this->GetCookieStore();
  GURL url_foobar("http://foo.bar.com");

  // More specific sub-domain than allowed.
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "a=1; domain=.yo.foo.bar.com"));

// The iOS networking stack uses the iOS cookie parser, which we do not
// control. Its handling of multiple domain= values in cookie string varies
// depending on iOS version. See https://crbug.com/639167
#if !defined(OS_IOS)
  // Regression test for https://crbug.com/601786
  EXPECT_FALSE(
      this->SetCookie(cs, url_foobar, "a=1; domain=.yo.foo.bar.com; domain="));
#endif  // !defined(OS_IOS)

  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "b=2; domain=.foo.com"));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "c=3; domain=.bar.foo.com"));

  // Different TLD, but the rest is a substring.
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "d=4; domain=.foo.bar.com.net"));

  // A substring that isn't really a parent domain.
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "e=5; domain=ar.com"));

  // Completely invalid domains:
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "f=6; domain=."));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "g=7; domain=/"));
  EXPECT_FALSE(
      this->SetCookie(cs, url_foobar, "h=8; domain=http://foo.bar.com"));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "i=9; domain=..foo.bar.com"));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "j=10; domain=..bar.com"));

  // Make sure there isn't something quirky in the domain canonicalization
  // that supports full URL semantics.
  EXPECT_FALSE(
      this->SetCookie(cs, url_foobar, "k=11; domain=.foo.bar.com?blah"));
  EXPECT_FALSE(
      this->SetCookie(cs, url_foobar, "l=12; domain=.foo.bar.com/blah"));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "m=13; domain=.foo.bar.com:80"));
  EXPECT_FALSE(this->SetCookie(cs, url_foobar, "n=14; domain=.foo.bar.com:"));
  EXPECT_FALSE(
      this->SetCookie(cs, url_foobar, "o=15; domain=.foo.bar.com#sup"));

  this->MatchCookieLines(std::string(), this->GetCookies(cs, url_foobar));
}

// Make sure the cookie code hasn't gotten its subdomain string handling
// reversed, missed a suffix check, etc.  It's important here that the two
// hosts below have the same domain + registry.
TYPED_TEST_P(CookieStoreTest, InvalidDomainSameDomainAndRegistry) {
  CookieStore* cs = this->GetCookieStore();
  GURL url_foocom("http://foo.com.com");
  EXPECT_FALSE(this->SetCookie(cs, url_foocom, "a=1; domain=.foo.com.com.com"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url_foocom));
}

// Setting the domain without a dot on a parent domain should add a domain
// cookie.
TYPED_TEST_P(CookieStoreTest, DomainWithoutLeadingDotParentDomain) {
  CookieStore* cs = this->GetCookieStore();
  GURL url_hosted("http://manage.hosted.filefront.com");
  GURL url_filefront("http://www.filefront.com");
  EXPECT_TRUE(this->SetCookie(cs, url_hosted, "sawAd=1; domain=filefront.com"));
  this->MatchCookieLines("sawAd=1", this->GetCookies(cs, url_hosted));
  this->MatchCookieLines("sawAd=1", this->GetCookies(cs, url_filefront));
}

// Even when the specified domain matches the domain of the URL exactly, treat
// it as setting a domain cookie.
TYPED_TEST_P(CookieStoreTest, DomainWithoutLeadingDotSameDomain) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://www.foo.com");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1; domain=www.foo.com"));
  this->MatchCookieLines("a=1", this->GetCookies(cs, url));
  this->MatchCookieLines("a=1",
                         this->GetCookies(cs, GURL("http://sub.www.foo.com")));
  this->MatchCookieLines(
      std::string(), this->GetCookies(cs, GURL("http://something-else.com")));
}

// Test that the domain specified in cookie string is treated case-insensitive
TYPED_TEST_P(CookieStoreTest, CaseInsensitiveDomainTest) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://www.foo.com");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1; domain=.FOO.COM"));
  EXPECT_TRUE(this->SetCookie(cs, url, "b=2; domain=.wWw.fOO.cOM"));
  this->MatchCookieLines("a=1; b=2", this->GetCookies(cs, url));
}

TYPED_TEST_P(CookieStoreTest, TestIpAddress) {
  GURL url_ip("http://1.2.3.4/weee");
  CookieStore* cs = this->GetCookieStore();
  EXPECT_TRUE(this->SetCookie(cs, url_ip, kValidCookieLine));
  this->MatchCookieLines("A=B", this->GetCookies(cs, url_ip));
}

// IP addresses should not be able to set domain cookies.
TYPED_TEST_P(CookieStoreTest, TestIpAddressNoDomainCookies) {
  GURL url_ip("http://1.2.3.4/weee");
  CookieStore* cs = this->GetCookieStore();
  EXPECT_FALSE(this->SetCookie(cs, url_ip, "b=2; domain=.1.2.3.4"));
  EXPECT_FALSE(this->SetCookie(cs, url_ip, "c=3; domain=.3.4"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url_ip));
  // It should be allowed to set a cookie if domain= matches the IP address
  // exactly.  This matches IE/Firefox, even though it seems a bit wrong.
  EXPECT_FALSE(this->SetCookie(cs, url_ip, "b=2; domain=1.2.3.3"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url_ip));
  EXPECT_TRUE(this->SetCookie(cs, url_ip, "b=2; domain=1.2.3.4"));
  this->MatchCookieLines("b=2", this->GetCookies(cs, url_ip));
}

// Test a TLD setting cookies on itself.
TYPED_TEST_P(CookieStoreTest, TestTLD) {
  if (!TypeParam::supports_non_dotted_domains)
    return;
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://com/");

  // Allow setting on "com", (but only as a host cookie).
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1"));
  // Domain cookies can't be set.
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=.com"));
  // Exact matches between the domain attribute and the host are treated as
  // host cookies, not domain cookies.
  EXPECT_TRUE(this->SetCookie(cs, url, "c=3; domain=com"));

  this->MatchCookieLines("a=1; c=3", this->GetCookies(cs, url));

  // Make sure they don't show up for a normal .com, they should be host,
  // domain, cookies.
  this->MatchCookieLines(
      std::string(),
      this->GetCookies(cs, GURL("http://hopefully-no-cookies.com/")));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, GURL("http://.com/")));
}

// http://com. should be treated the same as http://com.
TYPED_TEST_P(CookieStoreTest, TestTLDWithTerminalDot) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://com./index.html");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1"));
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=.com."));
  this->MatchCookieLines("a=1", this->GetCookies(cs, url));
  this->MatchCookieLines(
      std::string(),
      this->GetCookies(cs, GURL("http://hopefully-no-cookies.com./")));
}

TYPED_TEST_P(CookieStoreTest, TestSubdomainSettingCookiesOnUnknownTLD) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://a.b");
  EXPECT_FALSE(this->SetCookie(cs, url, "a=1; domain=.b"));
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=b"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url));
}

TYPED_TEST_P(CookieStoreTest, TestSubdomainSettingCookiesOnKnownTLD) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://foo.com");
  EXPECT_FALSE(this->SetCookie(cs, url, "a=1; domain=.com"));
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=com"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url));
}

TYPED_TEST_P(CookieStoreTest, TestSubdomainSettingCookiesOnKnownDottedTLD) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://foo.co.uk");
  EXPECT_FALSE(this->SetCookie(cs, url, "a=1; domain=.co.uk"));
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=.uk"));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, url));
  this->MatchCookieLines(
      std::string(), this->GetCookies(cs, GURL("http://something-else.co.uk")));
  this->MatchCookieLines(
      std::string(), this->GetCookies(cs, GURL("http://something-else.uk")));
}

// Intranet URLs should only be able to set host cookies.
TYPED_TEST_P(CookieStoreTest, TestSettingCookiesOnUnknownTLD) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://b");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1"));
  EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=.b"));
  this->MatchCookieLines("a=1", this->GetCookies(cs, url));
}

// Exact matches between the domain attribute and an intranet host are
// treated as host cookies, not domain cookies.
TYPED_TEST_P(CookieStoreTest, TestSettingCookiesWithHostDomainOnUnknownTLD) {
  if (!TypeParam::supports_non_dotted_domains)
    return;
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://b");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1; domain=b"));

  this->MatchCookieLines("a=1", this->GetCookies(cs, url));

  // Make sure it doesn't show up for an intranet subdomain, it should be
  // a host, not domain, cookie.
  this->MatchCookieLines(
      std::string(),
      this->GetCookies(cs, GURL("http://hopefully-no-cookies.b/")));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, GURL("http://.b/")));
}

// Test reading/writing cookies when the domain ends with a period,
// as in "www.foo.com."
TYPED_TEST_P(CookieStoreTest, TestHostEndsWithDot) {
  CookieStore* cs = this->GetCookieStore();
  GURL url("http://www.foo.com");
  GURL url_with_dot("http://www.foo.com.");
  EXPECT_TRUE(this->SetCookie(cs, url, "a=1"));
  this->MatchCookieLines("a=1", this->GetCookies(cs, url));

  // Do not share cookie space with the dot version of domain.
  // Note: this is not what FireFox does, but it _is_ what IE+Safari do.
  if (TypeParam::preserves_trailing_dots) {
    EXPECT_FALSE(this->SetCookie(cs, url, "b=2; domain=.www.foo.com."));
    this->MatchCookieLines("a=1", this->GetCookies(cs, url));
    EXPECT_TRUE(this->SetCookie(cs, url_with_dot, "b=2; domain=.foo.com."));
    this->MatchCookieLines("b=2", this->GetCookies(cs, url_with_dot));
  } else {
    EXPECT_TRUE(this->SetCookie(cs, url, "b=2; domain=.www.foo.com."));
    this->MatchCookieLines("a=1 b=2", this->GetCookies(cs, url));
    // Setting this cookie should fail, since the trailing dot on the domain
    // isn't preserved, and then the domain mismatches the URL.
    EXPECT_FALSE(this->SetCookie(cs, url_with_dot, "b=2; domain=.foo.com."));
  }

  // Make sure there weren't any side effects.
  this->MatchCookieLines(
      std::string(),
      this->GetCookies(cs, GURL("http://hopefully-no-cookies.com/")));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, GURL("http://.com/")));
}

TYPED_TEST_P(CookieStoreTest, InvalidScheme) {
  if (!TypeParam::filters_schemes)
    return;

  CookieStore* cs = this->GetCookieStore();
  EXPECT_FALSE(this->SetCookie(cs, this->ftp_foo_.url(), kValidCookieLine));
}

TYPED_TEST_P(CookieStoreTest, InvalidScheme_Read) {
  if (!TypeParam::filters_schemes)
    return;

  const std::string kValidDomainCookieLine =
      this->http_www_foo_.Format("A=B; path=/; domain=%D");

  CookieStore* cs = this->GetCookieStore();
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(), kValidDomainCookieLine));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->ftp_foo_.url()));
  EXPECT_EQ(0U, this->GetCookieListWithOptions(cs, this->ftp_foo_.url(),
                                               CookieOptions())
                    .size());
}

TYPED_TEST_P(CookieStoreTest, PathTest) {
  CookieStore* cs = this->GetCookieStore();
  std::string url("http://www.foo.com");
  EXPECT_TRUE(this->SetCookie(cs, GURL(url), "A=B; path=/wee"));
  this->MatchCookieLines("A=B", this->GetCookies(cs, GURL(url + "/wee")));
  this->MatchCookieLines("A=B", this->GetCookies(cs, GURL(url + "/wee/")));
  this->MatchCookieLines("A=B", this->GetCookies(cs, GURL(url + "/wee/war")));
  this->MatchCookieLines(
      "A=B", this->GetCookies(cs, GURL(url + "/wee/war/more/more")));
  if (!TypeParam::has_path_prefix_bug)
    this->MatchCookieLines(std::string(),
                           this->GetCookies(cs, GURL(url + "/weehee")));
  this->MatchCookieLines(std::string(), this->GetCookies(cs, GURL(url + "/")));

  // If we add a 0 length path, it should default to /
  EXPECT_TRUE(this->SetCookie(cs, GURL(url), "A=C; path="));
  this->MatchCookieLines("A=B; A=C", this->GetCookies(cs, GURL(url + "/wee")));
  this->MatchCookieLines("A=C", this->GetCookies(cs, GURL(url + "/")));
}

TYPED_TEST_P(CookieStoreTest, EmptyExpires) {
  CookieStore* cs = this->GetCookieStore();
  CookieOptions options;
  if (!TypeParam::supports_http_only)
    options.set_include_httponly();
  GURL url("http://www7.ipdl.inpit.go.jp/Tokujitu/tjkta.ipdl?N0000=108");
  std::string set_cookie_line =
      "ACSTM=20130308043820420042; path=/; domain=ipdl.inpit.go.jp; Expires=";
  std::string cookie_line = "ACSTM=20130308043820420042";

  this->SetCookieWithOptions(cs, url, set_cookie_line, options);
  this->MatchCookieLines(cookie_line,
                         this->GetCookiesWithOptions(cs, url, options));

  options.set_server_time(base::Time::Now() - base::TimeDelta::FromHours(1));
  this->SetCookieWithOptions(cs, url, set_cookie_line, options);
  this->MatchCookieLines(cookie_line,
                         this->GetCookiesWithOptions(cs, url, options));

  options.set_server_time(base::Time::Now() + base::TimeDelta::FromHours(1));
  this->SetCookieWithOptions(cs, url, set_cookie_line, options);
  this->MatchCookieLines(cookie_line,
                         this->GetCookiesWithOptions(cs, url, options));
}

TYPED_TEST_P(CookieStoreTest, HttpOnlyTest) {
  if (!TypeParam::supports_http_only)
    return;

  CookieStore* cs = this->GetCookieStore();
  CookieOptions options;
  options.set_include_httponly();

  // Create a httponly cookie.
  EXPECT_TRUE(this->SetCookieWithOptions(cs, this->http_www_foo_.url(),
                                         "A=B; httponly", options));

  // Check httponly read protection.
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("A=B", this->GetCookiesWithOptions(
                                    cs, this->http_www_foo_.url(), options));

  // Check httponly overwrite protection.
  EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(), "A=C"));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("A=B", this->GetCookiesWithOptions(
                                    cs, this->http_www_foo_.url(), options));
  EXPECT_TRUE(this->SetCookieWithOptions(cs, this->http_www_foo_.url(), "A=C",
                                         options));
  this->MatchCookieLines("A=C",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Check httponly create protection.
  EXPECT_FALSE(this->SetCookie(cs, this->http_www_foo_.url(), "B=A; httponly"));
  this->MatchCookieLines("A=C", this->GetCookiesWithOptions(
                                    cs, this->http_www_foo_.url(), options));
  EXPECT_TRUE(this->SetCookieWithOptions(cs, this->http_www_foo_.url(),
                                         "B=A; httponly", options));
  this->MatchCookieLines(
      "A=C; B=A",
      this->GetCookiesWithOptions(cs, this->http_www_foo_.url(), options));
  this->MatchCookieLines("A=C",
                         this->GetCookies(cs, this->http_www_foo_.url()));
}

TYPED_TEST_P(CookieStoreTest, TestCookieDeletion) {
  CookieStore* cs = this->GetCookieStore();

  // Create a session cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), kValidCookieLine));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete it via Max-Age.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine) + "; max-age=0"));
  this->MatchCookieLineWithTimeout(cs, this->http_www_foo_.url(),
                                   std::string());

  // Create a session cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), kValidCookieLine));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete it via Expires.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine) +
                                  "; expires=Mon, 18-Apr-1977 22:50:13 GMT"));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Create a persistent cookie.
  EXPECT_TRUE(this->SetCookie(
      cs, this->http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-22 22:50:13 GMT"));

  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete it via Max-Age.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine) + "; max-age=0"));
  this->MatchCookieLineWithTimeout(cs, this->http_www_foo_.url(),
                                   std::string());

  // Create a persistent cookie.
  EXPECT_TRUE(this->SetCookie(
      cs, this->http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete it via Expires.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine) +
                                  "; expires=Mon, 18-Apr-1977 22:50:13 GMT"));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Create a persistent cookie.
  EXPECT_TRUE(this->SetCookie(
      cs, this->http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Check that it is not deleted with significant enough clock skew.
  base::Time server_time;
  EXPECT_TRUE(base::Time::FromString("Sun, 17-Apr-1977 22:50:13 GMT",
                                     &server_time));
  EXPECT_TRUE(this->SetCookieWithServerTime(
      cs, this->http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-1977 22:50:13 GMT",
      server_time));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Create a persistent cookie.
  EXPECT_TRUE(this->SetCookie(
      cs, this->http_www_foo_.url(),
      std::string(kValidCookieLine) + "; expires=Mon, 18-Apr-22 22:50:13 GMT"));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete it via Expires, with a unix epoch of 0.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine) +
                                  "; expires=Thu, 1-Jan-1970 00:00:00 GMT"));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
}

TYPED_TEST_P(CookieStoreTest, TestDeleteAll) {
  CookieStore* cs = this->GetCookieStore();

  // Set a session cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), kValidCookieLine));
  EXPECT_EQ("A=B", this->GetCookies(cs, this->http_www_foo_.url()));

  // Set a persistent cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              "C=D; expires=Mon, 18-Apr-22 22:50:13 GMT"));

  EXPECT_EQ(2u, this->GetAllCookies(cs).size());

  // Delete both, and make sure it works
  EXPECT_EQ(2u, this->DeleteAll(cs));
  EXPECT_EQ(0u, this->GetAllCookies(cs).size());
}

TYPED_TEST_P(CookieStoreTest, TestDeleteAllCreatedInTimeRange) {
  CookieStore* cs = this->GetCookieStore();
  const base::Time last_month = base::Time::Now() -
                                base::TimeDelta::FromDays(30);
  const base::Time last_minute = base::Time::Now() -
                                 base::TimeDelta::FromMinutes(1);
  const base::Time next_minute = base::Time::Now() +
                                 base::TimeDelta::FromMinutes(1);
  const base::Time next_month = base::Time::Now() +
                                base::TimeDelta::FromDays(30);

  // Add a cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B"));
  // Check that the cookie is in the store.
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Remove cookies in empty intervals.
  EXPECT_EQ(0u, this->DeleteCreatedInTimeRange(
                    cs, CookieStore::TimeRange(last_month, last_minute)));
  EXPECT_EQ(0u, this->DeleteCreatedInTimeRange(
                    cs, CookieStore::TimeRange(next_minute, next_month)));
  // Check that the cookie is still there.
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Remove the cookie with an interval defined by two dates.
  EXPECT_EQ(1u, this->DeleteCreatedInTimeRange(
                    cs, CookieStore::TimeRange(last_minute, next_minute)));
  // Check that the cookie disappeared.
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Add another cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "C=D"));
  // Check that the cookie is in the store.
  this->MatchCookieLines("C=D",
                         this->GetCookies(cs, this->http_www_foo_.url()));

  // Remove the cookie with a null ending time.
  EXPECT_EQ(1u, this->DeleteCreatedInTimeRange(
                    cs, CookieStore::TimeRange(last_minute, base::Time())));
  // Check that the cookie disappeared.
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
}

TYPED_TEST_P(CookieStoreTest, TestDeleteAllWithInfo) {
  CookieStore* cs = this->GetCookieStore();
  base::Time now = base::Time::Now();
  base::Time last_month = base::Time::Now() - base::TimeDelta::FromDays(30);
  base::Time last_minute = base::Time::Now() - base::TimeDelta::FromMinutes(1);

  // These 3 cookies match the time range and host.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "C=D"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "Y=Z"));
  EXPECT_TRUE(this->SetCookie(cs, this->https_www_foo_.url(), "E=B"));

  // Delete cookies.
  CookieDeletionInfo delete_info(now, base::Time::Max());
  delete_info.value_for_testing = "B";
  EXPECT_EQ(2u,  // Deletes A=B, E=B
            this->DeleteAllCreatedInTimeRange(cs, std::move(delete_info)));

  // Check that we deleted the right ones.
  this->MatchCookieLines("C=D;Y=Z",
                         this->GetCookies(cs, this->https_www_foo_.url()));

  // Finally, check that we don't delete cookies when our time range is off.
  delete_info = CookieDeletionInfo(last_month, last_minute);
  delete_info.value_for_testing = "D";
  EXPECT_EQ(0u, this->DeleteAllCreatedInTimeRange(cs, std::move(delete_info)));
  this->MatchCookieLines("C=D;Y=Z",
                         this->GetCookies(cs, this->https_www_foo_.url()));
  // Same thing, but with a good time range.
  delete_info = CookieDeletionInfo(now, base::Time::Max());
  delete_info.value_for_testing = "D";
  EXPECT_EQ(1u, this->DeleteAllCreatedInTimeRange(cs, std::move(delete_info)));
  this->MatchCookieLines("Y=Z",
                         this->GetCookies(cs, this->https_www_foo_.url()));
}

TYPED_TEST_P(CookieStoreTest, TestSecure) {
  CookieStore* cs = this->GetCookieStore();

  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B"));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->https_www_foo_.url()));

  EXPECT_TRUE(this->SetCookie(cs, this->https_www_foo_.url(), "A=B; secure"));
  // The secure should overwrite the non-secure.
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->https_www_foo_.url()));

  EXPECT_TRUE(this->SetCookie(cs, this->https_www_foo_.url(), "D=E; secure"));
  this->MatchCookieLines(std::string(),
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("A=B; D=E",
                         this->GetCookies(cs, this->https_www_foo_.url()));

  EXPECT_TRUE(this->SetCookie(cs, this->https_www_foo_.url(), "A=B"));
  // The non-secure should overwrite the secure.
  this->MatchCookieLines("A=B",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  this->MatchCookieLines("D=E; A=B",
                         this->GetCookies(cs, this->https_www_foo_.url()));
}

// Formerly NetUtilTest.CookieTest back when we used wininet's cookie handling.
TYPED_TEST_P(CookieStoreTest, NetUtilCookieTest) {
  const GURL test_url("http://mojo.jojo.foo.com/");

  CookieStore* cs = this->GetCookieStore();

  EXPECT_TRUE(this->SetCookie(cs, test_url, "foo=bar"));
  std::string value = this->GetCookies(cs, test_url);
  this->MatchCookieLines("foo=bar", value);

  // test that we can retrieve all cookies:
  EXPECT_TRUE(this->SetCookie(cs, test_url, "x=1"));
  EXPECT_TRUE(this->SetCookie(cs, test_url, "y=2"));

  std::string result = this->GetCookies(cs, test_url);
  EXPECT_FALSE(result.empty());
  EXPECT_NE(result.find("x=1"), std::string::npos) << result;
  EXPECT_NE(result.find("y=2"), std::string::npos) << result;
}

TYPED_TEST_P(CookieStoreTest, OverwritePersistentCookie) {
  GURL url_foo("http://www.foo.com/");
  GURL url_chromium("http://chromium.org");
  CookieStore* cs = this->GetCookieStore();

  // Insert a cookie "a" for path "/path1"
  EXPECT_TRUE(this->SetCookie(cs, url_foo,
                              "a=val1; path=/path1; "
                              "expires=Mon, 18-Apr-22 22:50:13 GMT"));

  // Insert a cookie "b" for path "/path1"
  EXPECT_TRUE(this->SetCookie(cs, url_foo,
                              "b=val1; path=/path1; "
                              "expires=Mon, 18-Apr-22 22:50:14 GMT"));

  // Insert a cookie "b" for path "/path1", that is httponly. This should
  // overwrite the non-http-only version.
  CookieOptions allow_httponly;
  allow_httponly.set_include_httponly();
  EXPECT_TRUE(this->SetCookieWithOptions(cs, url_foo,
                                         "b=val2; path=/path1; httponly; "
                                         "expires=Mon, 18-Apr-22 22:50:14 GMT",
                                         allow_httponly));

  // Insert a cookie "a" for path "/path1". This should overwrite.
  EXPECT_TRUE(this->SetCookie(cs, url_foo,
                              "a=val33; path=/path1; "
                              "expires=Mon, 18-Apr-22 22:50:14 GMT"));

  // Insert a cookie "a" for path "/path2". This should NOT overwrite
  // cookie "a", since the path is different.
  EXPECT_TRUE(this->SetCookie(cs, url_foo,
                              "a=val9; path=/path2; "
                              "expires=Mon, 18-Apr-22 22:50:14 GMT"));

  // Insert a cookie "a" for path "/path1", but this time for "chromium.org".
  // Although the name and path match, the hostnames do not, so shouldn't
  // overwrite.
  EXPECT_TRUE(this->SetCookie(cs, url_chromium,
                              "a=val99; path=/path1; "
                              "expires=Mon, 18-Apr-22 22:50:14 GMT"));

  if (TypeParam::supports_http_only) {
    this->MatchCookieLines(
        "a=val33", this->GetCookies(cs, GURL("http://www.foo.com/path1")));
  } else {
    this->MatchCookieLines(
        "a=val33; b=val2",
        this->GetCookies(cs, GURL("http://www.foo.com/path1")));
  }
  this->MatchCookieLines(
      "a=val9", this->GetCookies(cs, GURL("http://www.foo.com/path2")));
  this->MatchCookieLines(
      "a=val99", this->GetCookies(cs, GURL("http://chromium.org/path1")));
}

// Note that accepting an empty name is contrary to spec; see
// https://tools.ietf.org/html/rfc6265#section-4.1.1.  However, we do it
// for web compatibility; see http://inikulin.github.io/cookie-compat/
// (specifically the "foo" and "=a" tests).  This test is present in Chromium
// so that a flag is raised if this behavior is changed.
// On IOS we use the system cookie store which has Safari's behavior, so
// the test is skipped.
TYPED_TEST_P(CookieStoreTest, EmptyName) {
  if (TypeParam::forbids_setting_empty_name)
    return;

  GURL url_foo("http://www.foo.com/");
  CookieStore* cs = this->GetCookieStore();

  CookieOptions options;
  if (!TypeParam::supports_http_only)
    options.set_include_httponly();
  EXPECT_TRUE(this->SetCookieWithOptions(cs, url_foo, "a", options));
  CookieList list = this->GetAllCookiesForURL(cs, url_foo);
  EXPECT_EQ(1u, list.size());
  EXPECT_EQ("", list[0].Name());
  EXPECT_EQ("a", list[0].Value());
  EXPECT_EQ(1u, this->DeleteAll(cs));

  EXPECT_TRUE(this->SetCookieWithOptions(cs, url_foo, "=b", options));
  list = this->GetAllCookiesForURL(cs, url_foo);
  EXPECT_EQ(1u, list.size());
  EXPECT_EQ("", list[0].Name());
  EXPECT_EQ("b", list[0].Value());
  EXPECT_EQ(1u, this->DeleteAll(cs));
}

TYPED_TEST_P(CookieStoreTest, CookieOrdering) {
  // Put a random set of cookies into a store and make sure they're returned in
  // the right order.
  // Cookies should be sorted by path length and creation time, as per RFC6265.
  CookieStore* cs = this->GetCookieStore();
  EXPECT_TRUE(
      this->SetCookie(cs, GURL("http://d.c.b.a.foo.com/aa/x.html"), "c=1"));
  EXPECT_TRUE(this->SetCookie(cs, GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                              "d=1; domain=b.a.foo.com"));
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(
      TypeParam::creation_time_granularity_in_ms));
  EXPECT_TRUE(this->SetCookie(cs, GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                              "a=4; domain=b.a.foo.com"));
  base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(
      TypeParam::creation_time_granularity_in_ms));
  EXPECT_TRUE(this->SetCookie(cs, GURL("http://c.b.a.foo.com/aa/bb/cc/x.html"),
                              "e=1; domain=c.b.a.foo.com"));
  EXPECT_TRUE(
      this->SetCookie(cs, GURL("http://d.c.b.a.foo.com/aa/bb/x.html"), "b=1"));
  EXPECT_TRUE(this->SetCookie(cs, GURL("http://news.bbc.co.uk/midpath/x.html"),
                              "g=10"));
  EXPECT_EQ("d=1; a=4; e=1; b=1; c=1",
            this->GetCookies(cs, GURL("http://d.c.b.a.foo.com/aa/bb/cc/dd")));

  CookieOptions options;
  CookieList cookies = this->GetCookieListWithOptions(
      cs, GURL("http://d.c.b.a.foo.com/aa/bb/cc/dd"), options);
  CookieList::const_iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("d", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("a", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("e", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("b", it->Name());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("c", it->Name());

  EXPECT_TRUE(++it == cookies.end());
}

// Check that GetAllCookiesAsync returns cookies from multiple domains, in the
// correct order.
TYPED_TEST_P(CookieStoreTest, GetAllCookiesAsync) {
  CookieStore* cs = this->GetCookieStore();

  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B; path=/a"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_baz_com_.url(), "C=D;/"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_bar_com_.url(), "E=F; path=/bar"));

  // Check cookies for url.
  CookieList cookies = this->GetAllCookies(cs);
  CookieList::const_iterator it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(this->http_bar_com_.host(), it->Domain());
  EXPECT_EQ("/bar", it->Path());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("F", it->Value());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ(this->http_www_foo_.host(), it->Domain());
  EXPECT_EQ("/a", it->Path());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ(this->http_baz_com_.host(), it->Domain());
  EXPECT_EQ("/", it->Path());
  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("D", it->Value());

  ASSERT_TRUE(++it == cookies.end());
}

TYPED_TEST_P(CookieStoreTest, DeleteCookieAsync) {
  CookieStore* cs = this->GetCookieStore();

  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=A1; path=/"));
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(), "A=A2; path=/foo"));
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(), "A=A3; path=/bar"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "B=B1; path=/"));
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(), "B=B2; path=/foo"));
  EXPECT_TRUE(
      this->SetCookie(cs, this->http_www_foo_.url(), "B=B3; path=/bar"));

  this->DeleteCookie(cs, this->http_www_foo_.AppendPath("foo/bar"), "A");

  CookieList cookies = this->GetAllCookies(cs);
  size_t expected_size = 4;
  EXPECT_EQ(expected_size, cookies.size());
  for (const auto& cookie : cookies) {
    EXPECT_NE("A1", cookie.Value());
    EXPECT_NE("A2", cookie.Value());
  }
}

TYPED_TEST_P(CookieStoreTest, DeleteCanonicalCookieAsync) {
  CookieStore* cs = this->GetCookieStore();

  // Set two cookies with the same name, and make sure both are set.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=B;Path=/foo"));
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=C;Path=/bar"));
  EXPECT_EQ(2u, this->GetAllCookies(cs).size());
  EXPECT_EQ("A=B", this->GetCookies(cs, this->www_foo_foo_.url()));
  EXPECT_EQ("A=C", this->GetCookies(cs, this->www_foo_bar_.url()));

  // Delete the "/foo" cookie, and make sure only it was deleted.
  CookieList cookies = this->GetCookieListWithOptions(
      cs, this->www_foo_foo_.url(), CookieOptions());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ(1u, this->DeleteCanonicalCookie(cs, cookies[0]));
  EXPECT_EQ(1u, this->GetAllCookies(cs).size());
  EXPECT_EQ("", this->GetCookies(cs, this->www_foo_foo_.url()));
  EXPECT_EQ("A=C", this->GetCookies(cs, this->www_foo_bar_.url()));

  // Deleting the "/foo" cookie again should fail.
  EXPECT_EQ(0u, this->DeleteCanonicalCookie(cs, cookies[0]));

  // Try to delete the "/bar" cookie after overwriting it with a new cookie.
  cookies = this->GetCookieListWithOptions(cs, this->www_foo_bar_.url(),
                                           CookieOptions());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(), "A=D;Path=/bar"));
  EXPECT_EQ(0u, this->DeleteCanonicalCookie(cs, cookies[0]));
  EXPECT_EQ(1u, this->GetAllCookies(cs).size());
  EXPECT_EQ("A=D", this->GetCookies(cs, this->www_foo_bar_.url()));

  // Delete the new "/bar" cookie.
  cookies = this->GetCookieListWithOptions(cs, this->www_foo_bar_.url(),
                                           CookieOptions());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ(1u, this->DeleteCanonicalCookie(cs, cookies[0]));
  EXPECT_EQ(0u, this->GetAllCookies(cs).size());
  EXPECT_EQ("", this->GetCookies(cs, this->www_foo_bar_.url()));
}

TYPED_TEST_P(CookieStoreTest, DeleteSessionCookie) {
  CookieStore* cs = this->GetCookieStore();
  // Create a session cookie and a persistent cookie.
  EXPECT_TRUE(this->SetCookie(cs, this->http_www_foo_.url(),
                              std::string(kValidCookieLine)));
  EXPECT_TRUE(this->SetCookie(
      cs, this->http_www_foo_.url(),
      this->http_www_foo_.Format("C=D; path=/; domain=%D;"
                                 "expires=Mon, 18-Apr-22 22:50:13 GMT")));
  this->MatchCookieLines("A=B; C=D",
                         this->GetCookies(cs, this->http_www_foo_.url()));
  // Delete the session cookie.
  this->DeleteSessionCookies(cs);
  // Check that the session cookie has been deleted but not the persistent one.
  EXPECT_EQ("C=D", this->GetCookies(cs, this->http_www_foo_.url()));
}

TYPED_TEST_P(CookieStoreTest, TimeRangeValues) {
  CookieStore::TimeRange range;
  EXPECT_EQ(base::Time(), range.start());
  EXPECT_EQ(base::Time(), range.end());

  const base::Time kTestStart = base::Time::FromDoubleT(1000);
  const base::Time kTestEnd = base::Time::FromDoubleT(10000);

  EXPECT_EQ(kTestStart,
            CookieStore::TimeRange(kTestStart, base::Time()).start());
  EXPECT_EQ(base::Time(),
            CookieStore::TimeRange(kTestStart, base::Time()).end());

  EXPECT_EQ(kTestStart, CookieStore::TimeRange(kTestStart, kTestEnd).start());
  EXPECT_EQ(kTestEnd, CookieStore::TimeRange(kTestStart, kTestEnd).end());

  CookieStore::TimeRange range2;
  range2.SetStart(kTestStart);
  EXPECT_EQ(kTestStart, range2.start());
  EXPECT_EQ(base::Time(), range2.end());
  range2.SetEnd(kTestEnd);
  EXPECT_EQ(kTestStart, range2.start());
  EXPECT_EQ(kTestEnd, range2.end());
}

TYPED_TEST_P(CookieStoreTest, TimeRangeContains) {
  // Default TimeRange matches all time values.
  CookieStore::TimeRange range;
  EXPECT_TRUE(range.Contains(base::Time::Now()));
  EXPECT_TRUE(range.Contains(base::Time::Max()));

  // With a start, but no end.
  const double kTestMinEpoch = 1000;
  range.SetStart(base::Time::FromDoubleT(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch - 1)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch + 1)));
  EXPECT_TRUE(range.Contains(base::Time::Max()));

  // With an end, but no start.
  const double kTestMaxEpoch = 10000000;
  range = CookieStore::TimeRange();
  range.SetEnd(base::Time::FromDoubleT(kTestMaxEpoch));
  EXPECT_TRUE(range.Contains(base::Time::Min()));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch - 1)));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch)));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch + 1)));
  EXPECT_FALSE(range.Contains(base::Time::Max()));

  // With both a start and an end.
  range.SetStart(base::Time::FromDoubleT(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch - 1)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch + 1)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch - 1)));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch)));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMaxEpoch + 1)));
  EXPECT_FALSE(range.Contains(base::Time::Max()));

  // And where start==end.
  range = CookieStore::TimeRange(base::Time::FromDoubleT(kTestMinEpoch),
                                 base::Time::FromDoubleT(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch - 1)));
  EXPECT_TRUE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch)));
  EXPECT_FALSE(range.Contains(base::Time::FromDoubleT(kTestMinEpoch + 1)));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchSessionControl) {
  CanonicalCookie persistent_cookie("persistent-cookie", "persistent-value",
                                    "persistent-domain", "persistent-path",
                                    /*creation=*/base::Time::Now(),
                                    /*expiration=*/base::Time::Max(),
                                    /*last_access=*/base::Time::Now(),
                                    /*secure=*/false,
                                    /*httponly=*/false,
                                    CookieSameSite::DEFAULT_MODE,
                                    CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CanonicalCookie session_cookie(
      "session-cookie", "session-value", "session-domain", "session-path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time(),
      /*last_access=*/base::Time::Now(),
      /*secure=*/false,
      /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  EXPECT_TRUE(delete_info.Matches(persistent_cookie));
  EXPECT_TRUE(delete_info.Matches(session_cookie));

  delete_info.session_control =
      CookieDeletionInfo::SessionControl::PERSISTENT_COOKIES;
  EXPECT_TRUE(delete_info.Matches(persistent_cookie));
  EXPECT_FALSE(delete_info.Matches(session_cookie));

  delete_info.session_control =
      CookieDeletionInfo::SessionControl::SESSION_COOKIES;
  EXPECT_FALSE(delete_info.Matches(persistent_cookie));
  EXPECT_TRUE(delete_info.Matches(session_cookie));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchHost) {
  CanonicalCookie domain_cookie("domain-cookie", "domain-cookie-value",
                                /*domain=*/".example.com", "/path",
                                /*creation=*/base::Time::Now(),
                                /*expiration=*/base::Time::Max(),
                                /*last_access=*/base::Time::Now(),
                                /*secure=*/false,
                                /*httponly=*/false,
                                CookieSameSite::DEFAULT_MODE,
                                CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CanonicalCookie host_cookie("host-cookie", "host-cookie-value",
                              /*domain=*/"thehost.hosting.com", "/path",
                              /*creation=*/base::Time::Now(),
                              /*expiration=*/base::Time::Max(),
                              /*last_access=*/base::Time::Now(),
                              /*secure=*/false,
                              /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
                              CookiePriority::COOKIE_PRIORITY_DEFAULT);

  EXPECT_TRUE(domain_cookie.IsDomainCookie());
  EXPECT_TRUE(host_cookie.IsHostCookie());

  CookieDeletionInfo delete_info;
  EXPECT_TRUE(delete_info.Matches(domain_cookie));
  EXPECT_TRUE(delete_info.Matches(host_cookie));

  delete_info.host = "thehost.hosting.com";
  EXPECT_FALSE(delete_info.Matches(domain_cookie));
  EXPECT_TRUE(delete_info.Matches(host_cookie));

  delete_info.host = "otherhost.hosting.com";
  EXPECT_FALSE(delete_info.Matches(domain_cookie));
  EXPECT_FALSE(delete_info.Matches(host_cookie));

  delete_info.host = "thehost.otherhosting.com";
  EXPECT_FALSE(delete_info.Matches(domain_cookie));
  EXPECT_FALSE(delete_info.Matches(host_cookie));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchName) {
  CanonicalCookie cookie1("cookie1-name", "cookie1-value",
                          /*domain=*/".example.com", "/path",
                          /*creation=*/base::Time::Now(),
                          /*expiration=*/base::Time::Max(),
                          /*last_access=*/base::Time::Now(),
                          /*secure=*/false,
                          /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
                          CookiePriority::COOKIE_PRIORITY_DEFAULT);
  CanonicalCookie cookie2("cookie2-name", "cookie2-value",
                          /*domain=*/".example.com", "/path",
                          /*creation=*/base::Time::Now(),
                          /*expiration=*/base::Time::Max(),
                          /*last_access=*/base::Time::Now(),
                          /*secure=*/false,
                          /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
                          CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.name = "cookie1-name";
  EXPECT_TRUE(delete_info.Matches(cookie1));
  EXPECT_FALSE(delete_info.Matches(cookie2));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchValue) {
  CanonicalCookie cookie1("cookie1-name", "cookie1-value",
                          /*domain=*/".example.com", "/path",
                          /*creation=*/base::Time::Now(),
                          /*expiration=*/base::Time::Max(),
                          /*last_access=*/base::Time::Now(),
                          /*secure=*/false,
                          /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
                          CookiePriority::COOKIE_PRIORITY_DEFAULT);
  CanonicalCookie cookie2("cookie2-name", "cookie2-value",
                          /*domain=*/".example.com", "/path",
                          /*creation=*/base::Time::Now(),
                          /*expiration=*/base::Time::Max(),
                          /*last_access=*/base::Time::Now(),
                          /*secure=*/false,
                          /*httponly=*/false, CookieSameSite::DEFAULT_MODE,
                          CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.value_for_testing = "cookie2-value";
  EXPECT_FALSE(delete_info.Matches(cookie1));
  EXPECT_TRUE(delete_info.Matches(cookie2));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchUrl) {
  CanonicalCookie cookie("cookie-name", "cookie-value",
                         /*domain=*/"www.example.com", "/path",
                         /*creation=*/base::Time::Now(),
                         /*expiration=*/base::Time::Max(),
                         /*last_access=*/base::Time::Now(),
                         /*secure=*/false,
                         /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
                         CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.url = GURL("https://www.example.com/path");
  EXPECT_TRUE(delete_info.Matches(cookie));

  delete_info.url = GURL("https://www.example.com/another/path");
  EXPECT_FALSE(delete_info.Matches(cookie));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoDomainMatchesDomain) {
  CookieDeletionInfo delete_info;

  const double kTestMinEpoch = 1000;
  const double kTestMaxEpoch = 10000000;
  delete_info.creation_range.SetStart(base::Time::FromDoubleT(kTestMinEpoch));
  delete_info.creation_range.SetEnd(base::Time::FromDoubleT(kTestMaxEpoch));

  auto create_cookie = [kTestMinEpoch](std::string cookie_domain) {
    CanonicalCookie cookie(
        /*name=*/"test-cookie",
        /*value=*/"cookie-value", cookie_domain,
        /*path=*/"cookie/path",
        /*creation=*/base::Time::FromDoubleT(kTestMinEpoch + 1),
        /*expiration=*/base::Time::Max(),
        /*last_access=*/base::Time::FromDoubleT(kTestMinEpoch + 1),
        /*secure=*/false,
        /*httponly=*/false,
        /*same_site=*/CookieSameSite::DEFAULT_MODE,
        /*priority=*/CookiePriority::COOKIE_PRIORITY_DEFAULT);
    return cookie;
  };

  // by default empty domain list and default match action will match.
  EXPECT_TRUE(delete_info.Matches(create_cookie("example.com")));

  const char kExtensionHostname[] = "mgndgikekgjfcpckkfioiadnlibdjbkf";

  // Only using the inclusion list because this is only testing
  // DomainMatchesDomainSet and not CookieStore::CookieDeletionInfo::Matches.
  delete_info.domains_and_ips_to_delete =
      std::set<std::string>({"example.com", "another.com", "192.168.0.1"});
  EXPECT_TRUE(delete_info.Matches(create_cookie(".example.com")));
  EXPECT_TRUE(delete_info.Matches(create_cookie("example.com")));
  EXPECT_TRUE(delete_info.Matches(create_cookie(".another.com")));
  EXPECT_TRUE(delete_info.Matches(create_cookie("192.168.0.1")));
  EXPECT_FALSE(delete_info.Matches(create_cookie(".nomatch.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("192.168.0.2")));
  EXPECT_FALSE(delete_info.Matches(create_cookie(kExtensionHostname)));
}

TYPED_TEST_P(CookieStoreTest, CookieDeletionInfoMatchesDomainList) {
  CookieDeletionInfo delete_info;

  auto create_cookie = [](std::string cookie_domain) {
    CanonicalCookie cookie(
        /*name=*/"test-cookie",
        /*value=*/"cookie-value", cookie_domain,
        /*path=*/"cookie/path",
        /*creation=*/base::Time::Now(),
        /*expiration=*/base::Time::Max(),
        /*last_access=*/base::Time::Now(),
        /*secure=*/false,
        /*httponly=*/false,
        /*same_site=*/CookieSameSite::DEFAULT_MODE,
        /*priority=*/CookiePriority::COOKIE_PRIORITY_DEFAULT);
    return cookie;
  };

  // With two empty lists (default) should match any domain.
  EXPECT_TRUE(delete_info.Matches(create_cookie("anything.com")));

  // With only an inclusion list.
  delete_info.domains_and_ips_to_delete =
      std::set<std::string>({"includea.com", "includeb.com"});
  EXPECT_TRUE(delete_info.Matches(create_cookie("includea.com")));
  EXPECT_TRUE(delete_info.Matches(create_cookie("includeb.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("anything.com")));

  // With only an exclusion list.
  delete_info.domains_and_ips_to_delete.clear();
  delete_info.domains_and_ips_to_ignore.insert("exclude.com");
  EXPECT_TRUE(delete_info.Matches(create_cookie("anything.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("exclude.com")));

  // Now with both lists populated.
  //
  // +----------------------+
  // | inclusion            |  outside.com
  // |                      |
  // |  left.com  +---------------------+
  // |            | mid.com | exclusion |
  // |            |         |           |
  // +------------|---------+           |
  //              |           right.com |
  //              |                     |
  //              +---------------------+
  delete_info.domains_and_ips_to_delete =
      std::set<std::string>({"left.com", "mid.com"});
  delete_info.domains_and_ips_to_ignore =
      std::set<std::string>({"mid.com", "right.com"});

  EXPECT_TRUE(delete_info.Matches(create_cookie("left.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("mid.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("right.com")));
  EXPECT_FALSE(delete_info.Matches(create_cookie("outside.com")));
}

REGISTER_TYPED_TEST_CASE_P(CookieStoreTest,
                           FilterTest,
                           SetCanonicalCookieTest,
                           SecureEnforcement,
                           EmptyKeyTest,
                           DomainTest,
                           DomainWithTrailingDotTest,
                           ValidSubdomainTest,
                           InvalidDomainTest,
                           InvalidDomainSameDomainAndRegistry,
                           DomainWithoutLeadingDotParentDomain,
                           DomainWithoutLeadingDotSameDomain,
                           CaseInsensitiveDomainTest,
                           TestIpAddress,
                           TestIpAddressNoDomainCookies,
                           TestTLD,
                           TestTLDWithTerminalDot,
                           TestSubdomainSettingCookiesOnUnknownTLD,
                           TestSubdomainSettingCookiesOnKnownTLD,
                           TestSubdomainSettingCookiesOnKnownDottedTLD,
                           TestSettingCookiesOnUnknownTLD,
                           TestSettingCookiesWithHostDomainOnUnknownTLD,
                           TestHostEndsWithDot,
                           InvalidScheme,
                           InvalidScheme_Read,
                           PathTest,
                           EmptyExpires,
                           HttpOnlyTest,
                           TestCookieDeletion,
                           TestDeleteAll,
                           TestDeleteAllCreatedInTimeRange,
                           TestDeleteAllWithInfo,
                           TestSecure,
                           NetUtilCookieTest,
                           OverwritePersistentCookie,
                           EmptyName,
                           CookieOrdering,
                           GetAllCookiesAsync,
                           DeleteCookieAsync,
                           DeleteCanonicalCookieAsync,
                           DeleteSessionCookie,
                           TimeRangeValues,
                           TimeRangeContains,
                           CookieDeletionInfoDomainMatchesDomain,
                           CookieDeletionInfoMatchesDomainList,
                           CookieDeletionInfoMatchSessionControl,
                           CookieDeletionInfoMatchHost,
                           CookieDeletionInfoMatchName,
                           CookieDeletionInfoMatchValue,
                           CookieDeletionInfoMatchUrl);

}  // namespace net

#endif  // NET_COOKIES_COOKIE_STORE_UNITTEST_H_
