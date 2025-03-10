// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/assistant/assistant_card_renderer.h"

#include <memory>

#include "ash/public/interfaces/ash_assistant_controller.mojom.h"
#include "ash/public/interfaces/constants.mojom.h"
#include "base/optional.h"
#include "chrome/browser/chromeos/profiles/profile_helper.h"
#include "components/user_manager/user_manager.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/render_widget_host_view.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "services/service_manager/public/cpp/connector.h"
#include "ui/app_list/answer_card_contents_registry.h"
#include "ui/views/controls/webview/web_contents_set_background_color.h"
#include "ui/views/controls/webview/webview.h"
#include "ui/views/view.h"

namespace chromeos {
namespace assistant {

namespace {

constexpr char kDataUriPrefix[] = "data:text/html,";

// AssistantCard ---------------------------------------------------------------

class AssistantCard : public content::WebContentsDelegate,
                      public content::WebContentsObserver {
 public:
  AssistantCard(const AccountId& account_id,
                ash::mojom::AssistantCardParamsPtr params,
                ash::mojom::AssistantCardRenderer::RenderCallback callback) {
    const user_manager::User* user =
        user_manager::UserManager::Get()->FindUser(account_id);

    if (!user) {
      LOG(WARNING) << "Unable to retrieve user for account_id.";
      return;
    }

    Profile* profile = chromeos::ProfileHelper::Get()->GetProfileByUser(user);

    if (!profile) {
      LOG(WARNING) << "Unable to retrieve profile for user.";
      return;
    }

    InitWebContents(profile, std::move(params));
    HandleWebContents(profile, std::move(callback));
  }

  ~AssistantCard() override {
    web_contents_->SetDelegate(nullptr);

    // When cards are rendered in the same process as ash, we need to release
    // the associated view registered in the AnswerCardContentsRegistry's
    // token-to-view map.
    if (app_list::AnswerCardContentsRegistry::Get() && embed_token_.has_value())
      app_list::AnswerCardContentsRegistry::Get()->Unregister(
          embed_token_.value());
  }

  // content::WebContentsDelegate:
  void ResizeDueToAutoResize(content::WebContents* web_contents,
                             const gfx::Size& new_size) override {
    web_view_->SetPreferredSize(new_size);
  }

 private:
  void InitWebContents(Profile* profile,
                       ash::mojom::AssistantCardParamsPtr params) {
    web_contents_.reset(
        content::WebContents::Create(content::WebContents::CreateParams(
            profile, content::SiteInstance::Create(profile))));

    // Use a transparent background.
    views::WebContentsSetBackgroundColor::CreateForWebContentsWithColor(
        web_contents_.get(), SK_ColorTRANSPARENT);

    Observe(web_contents_.get());
    web_contents_->SetDelegate(this);

    // Load the card's HTML data string into the web contents.
    content::NavigationController::LoadURLParams load_params(
        GURL(kDataUriPrefix + params->html));
    load_params.should_clear_history_list = true;
    load_params.transition_type = ui::PAGE_TRANSITION_AUTO_TOPLEVEL;
    web_contents_->GetController().LoadURLWithParams(load_params);

    // Enable auto-resizing, respecting the specified size parameters.
    web_contents_->GetRenderWidgetHostView()->EnableAutoResize(
        gfx::Size(params->min_width_dip, 0),
        gfx::Size(params->max_width_dip, INT_MAX));
  }

  void HandleWebContents(
      Profile* profile,
      ash::mojom::AssistantCardRenderer::RenderCallback callback) {
    // When rendering cards in the same process as ash, we register the view for
    // the card with the AnswerCardContentsRegistry's token-to-view map. The
    // token returned from the registry will uniquely identify the view.
    if (app_list::AnswerCardContentsRegistry::Get()) {
      web_view_ = std::make_unique<views::WebView>(profile);
      web_view_->set_owned_by_client();
      web_view_->SetResizeBackgroundColor(SK_ColorTRANSPARENT);
      web_view_->SetWebContents(web_contents_.get());

      embed_token_ = app_list::AnswerCardContentsRegistry::Get()->Register(
          web_view_.get());

      std::move(callback).Run(embed_token_.value());
    }
    // TODO(dmblack): Handle Mash case.
  }

  std::unique_ptr<content::WebContents> web_contents_;
  std::unique_ptr<views::WebView> web_view_;
  base::Optional<base::UnguessableToken> embed_token_;

  DISALLOW_COPY_AND_ASSIGN(AssistantCard);
};

}  // namespace

AssistantCardRenderer::AssistantCardRenderer(
    service_manager::Connector* connector)
    : assistant_controller_binding_(this) {
  // Bind to the Assistant controller in ash.
  ash::mojom::AshAssistantControllerPtr assistant_controller;
  connector->BindInterface(ash::mojom::kServiceName, &assistant_controller);
  ash::mojom::AssistantCardRendererPtr ptr;
  assistant_controller_binding_.Bind(mojo::MakeRequest(&ptr));
  assistant_controller->SetAssistantCardRenderer(std::move(ptr));
}

AssistantCardRenderer::~AssistantCardRenderer() = default;

void AssistantCardRenderer::Render(
    const AccountId& account_id,
    const base::UnguessableToken& id_token,
    ash::mojom::AssistantCardParamsPtr params,
    ash::mojom::AssistantCardRenderer::RenderCallback callback) {
  DCHECK(assistant_cards_.count(id_token) == 0);
  assistant_cards_[id_token] = std::make_unique<AssistantCard>(
      account_id, std::move(params), std::move(callback));
}

void AssistantCardRenderer::Release(const base::UnguessableToken& id_token) {
  assistant_cards_.erase(id_token);
}

}  // namespace assistant
}  // namespace chromeos
