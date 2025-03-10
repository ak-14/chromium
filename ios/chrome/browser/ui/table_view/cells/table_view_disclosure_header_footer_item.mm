// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "ios/chrome/browser/ui/table_view/cells/table_view_disclosure_header_footer_item.h"

#include "base/mac/foundation_util.h"
#include "base/numerics/math_constants.h"
#import "ios/chrome/browser/ui/table_view/cells/table_view_cells_constants.h"
#import "ios/chrome/browser/ui/table_view/chrome_table_view_styler.h"
#import "ios/chrome/browser/ui/uikit_ui_util.h"

#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

namespace {
// Rotates the disclosure back to its original position.
const float kToggleDisclosureOriginalPositionAngle = 0;

// 90 degree CCW rotation
constexpr float kRotationNinetyCCW = (90 / 180.0) * M_PI;
}

@implementation TableViewDisclosureHeaderFooterItem
@synthesize subtitleText = _subtitleText;
@synthesize text = _text;
@synthesize collapsed = _collapsed;

- (instancetype)initWithType:(NSInteger)type {
  self = [super initWithType:type];
  if (self) {
    self.cellClass = [TableViewDisclosureHeaderFooterView class];
  }
  return self;
}

- (void)configureHeaderFooterView:(UITableViewHeaderFooterView*)headerFooter
                       withStyler:(ChromeTableViewStyler*)styler {
  [super configureHeaderFooterView:headerFooter withStyler:styler];

  // Set the contentView backgroundColor, not the header's.
  headerFooter.contentView.backgroundColor = styler.tableViewBackgroundColor;

  TableViewDisclosureHeaderFooterView* header =
      base::mac::ObjCCastStrict<TableViewDisclosureHeaderFooterView>(
          headerFooter);
  header.titleLabel.text = self.text;
  header.subtitleLabel.text = self.subtitleText;
  DisclosureDirection direction =
      self.collapsed ? DisclosureDirectionRight : DisclosureDirectionDown;
  [header setInitialDirection:direction];
}

@end

#pragma mark - TableViewDisclosureHeaderFooterView

@interface TableViewDisclosureHeaderFooterView ()
// Animator that handles all cell animations.
@property(strong, nonatomic) UIViewPropertyAnimator* cellAnimator;
// ImageView that holds the disclosure accessory icon.
@property(strong, nonatomic) UIImageView* disclosureImageView;
@end

@implementation TableViewDisclosureHeaderFooterView
@synthesize cellAnimator = _cellAnimator;
@synthesize disclosureDirection = disclosureDirection;
@synthesize disclosureImageView = _disclosureImageView;
@synthesize subtitleLabel = _subtitleLabel;
@synthesize titleLabel = _titleLabel;

- (instancetype)initWithReuseIdentifier:(NSString*)reuseIdentifier {
  self = [super initWithReuseIdentifier:reuseIdentifier];
  if (self) {
    // Labels, set font sizes using dynamic type.
    _titleLabel = [[UILabel alloc] init];
    _titleLabel.font =
        [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    _subtitleLabel = [[UILabel alloc] init];
    _subtitleLabel.font =
        [UIFont preferredFontForTextStyle:UIFontTextStyleCaption1];
    _subtitleLabel.textColor = [UIColor lightGrayColor];

    // Vertical StackView.
    UIStackView* verticalStack = [[UIStackView alloc]
        initWithArrangedSubviews:@[ _titleLabel, _subtitleLabel ]];
    verticalStack.axis = UILayoutConstraintAxisVertical;
    verticalStack.spacing = kTableViewVerticalLabelStackSpacing;

    // Disclosure ImageView. Initial pointing direction is to the right.
    _disclosureImageView = [[UIImageView alloc]
        initWithImage:[UIImage imageNamed:@"table_view_cell_chevron"]];
    [_disclosureImageView
        setContentHuggingPriority:UILayoutPriorityDefaultHigh
                          forAxis:UILayoutConstraintAxisHorizontal];

    // Horizontal StackView.
    UIStackView* horizontalStack = [[UIStackView alloc]
        initWithArrangedSubviews:@[ verticalStack, _disclosureImageView ]];
    horizontalStack.axis = UILayoutConstraintAxisHorizontal;
    horizontalStack.spacing = kTableViewCellViewSpacing;
    horizontalStack.translatesAutoresizingMaskIntoConstraints = NO;
    horizontalStack.alignment = UIStackViewAlignmentCenter;

    // Add subviews to View Hierarchy.
    [self.contentView addSubview:horizontalStack];

    // Set and activate constraints.
    [NSLayoutConstraint activateConstraints:@[
      // Horizontal Stack Constraints.
      [horizontalStack.leadingAnchor
          constraintEqualToAnchor:self.contentView.leadingAnchor
                         constant:kTableViewCellViewSpacing],
      [horizontalStack.trailingAnchor
          constraintEqualToAnchor:self.contentView.trailingAnchor
                         constant:-kTableViewCellViewSpacing],
      [horizontalStack.topAnchor
          constraintGreaterThanOrEqualToAnchor:self.contentView.topAnchor
                                      constant:kTableViewCellViewSpacing],
      [horizontalStack.bottomAnchor
          constraintLessThanOrEqualToAnchor:self.contentView.bottomAnchor
                                   constant:-kTableViewCellViewSpacing],
      [horizontalStack.centerYAnchor
          constraintEqualToAnchor:self.contentView.centerYAnchor]
    ]];
  }
  return self;
}

#pragma mark - internal methods

- (void)addAnimationHighlightToAnimator {
  UIColor* originalBackgroundColor = self.contentView.backgroundColor;
  self.cellAnimator = [[UIViewPropertyAnimator alloc]
      initWithDuration:kTableViewCellSelectionAnimationDuration
                 curve:UIViewAnimationCurveLinear
            animations:^{
              self.contentView.backgroundColor =
                  UIColorFromRGB(kTableViewHighlightedCellColor,
                                 kTableViewHighlightedCellColorAlpha);
            }];
  __weak TableViewDisclosureHeaderFooterView* weakSelf = self;
  [self.cellAnimator addCompletion:^(UIViewAnimatingPosition finalPosition) {
    weakSelf.contentView.backgroundColor = originalBackgroundColor;
  }];
}

// When view is being initialized, it has not been added to the hierarchy yet.
// So, in order to set the initial direction, a non-animation transform is
// needed.
- (void)rotateToDirection:(DisclosureDirection)direction animate:(BOOL)animate {
  DisclosureDirection originalDirection = self.disclosureDirection;
  if (originalDirection != direction) {
    self.disclosureDirection = direction;
    CGFloat angle = direction == DisclosureDirectionDown
                        ? kRotationNinetyCCW
                        : kToggleDisclosureOriginalPositionAngle;
    if (animate) {
      __weak TableViewDisclosureHeaderFooterView* weakSelf = self;
      [self.cellAnimator addAnimations:^{
        weakSelf.disclosureImageView.transform =
            CGAffineTransformRotate(CGAffineTransformIdentity, angle);
      }];
    } else {
      self.disclosureImageView.transform =
          CGAffineTransformRotate(CGAffineTransformIdentity, angle);
    }
  }
}

#pragma mark - public methods

- (void)animateHighlight {
  [self addAnimationHighlightToAnimator];
  [self.cellAnimator startAnimation];
}

- (void)setInitialDirection:(DisclosureDirection)direction {
  [self rotateToDirection:direction animate:NO];
}

- (void)animateHighlightAndRotateToDirection:(DisclosureDirection)direction {
  [self addAnimationHighlightToAnimator];
  [self rotateToDirection:direction animate:YES];
  [self.cellAnimator startAnimation];
}

- (void)prepareForReuse {
  [super prepareForReuse];
  if (self.cellAnimator.isRunning)
    [self.cellAnimator stopAnimation:YES];
}

@end
