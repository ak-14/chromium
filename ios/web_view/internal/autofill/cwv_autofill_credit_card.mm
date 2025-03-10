// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "ios/web_view/internal/autofill/cwv_autofill_credit_card_internal.h"

#include "base/strings/sys_string_conversions.h"
#include "components/autofill/core/browser/credit_card.h"
#include "ios/web_view/internal/app/application_context.h"

#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

@interface CWVAutofillCreditCard ()

// Sets |value| for |type| in |_internalCard|.
- (void)setValue:(NSString*)value forType:(autofill::ServerFieldType)type;
// Gets |value| for |type| from |_internalCard|.
- (NSString*)valueForType:(autofill::ServerFieldType)type;

@end

@implementation CWVAutofillCreditCard {
  autofill::CreditCard _internalCard;
}

- (instancetype)initWithCreditCard:(const autofill::CreditCard&)creditCard {
  self = [super init];
  if (self) {
    _internalCard = creditCard;
  }
  return self;
}

#pragma mark - Public Methods

- (NSString*)cardHolderFullName {
  return [self valueForType:autofill::CREDIT_CARD_NAME_FULL];
}

- (void)setCardHolderFullName:(NSString*)cardHolderFullName {
  [self setValue:cardHolderFullName forType:autofill::CREDIT_CARD_NAME_FULL];
}

- (NSString*)cardNumber {
  return [self valueForType:autofill::CREDIT_CARD_NUMBER];
}

- (void)setCardNumber:(NSString*)cardNumber {
  [self setValue:cardNumber forType:autofill::CREDIT_CARD_NUMBER];
}

- (NSString*)networkName {
  return [self valueForType:autofill::CREDIT_CARD_TYPE];
}

- (NSString*)expirationMonth {
  return [self valueForType:autofill::CREDIT_CARD_EXP_MONTH];
}

- (void)setExpirationMonth:(NSString*)expirationMonth {
  [self setValue:expirationMonth forType:autofill::CREDIT_CARD_EXP_MONTH];
}

- (NSString*)expirationYear {
  return [self valueForType:autofill::CREDIT_CARD_EXP_4_DIGIT_YEAR];
}

- (void)setExpirationYear:(NSString*)expirationYear {
  [self setValue:expirationYear forType:autofill::CREDIT_CARD_EXP_4_DIGIT_YEAR];
}

- (NSString*)bankName {
  return base::SysUTF8ToNSString(_internalCard.bank_name());
}

- (BOOL)isSavedLocally {
  return _internalCard.record_type() == autofill::CreditCard::LOCAL_CARD;
}

#pragma mark - Internal

- (autofill::CreditCard*)internalCard {
  return &_internalCard;
}

#pragma mark - Private Methods

- (void)setValue:(NSString*)value forType:(autofill::ServerFieldType)type {
  const std::string& locale =
      ios_web_view::ApplicationContext::GetInstance()->GetApplicationLocale();
  _internalCard.SetInfo(type, base::SysNSStringToUTF16(value), locale);
}

- (NSString*)valueForType:(autofill::ServerFieldType)type {
  const std::string& locale =
      ios_web_view::ApplicationContext::GetInstance()->GetApplicationLocale();
  return base::SysUTF16ToNSString(_internalCard.GetInfo(type, locale));
}

@end
