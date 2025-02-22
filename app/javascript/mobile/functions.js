import $ from "jquery";
import Sugar from "../sugar";

window.toggleNavigation = function () {
  $("#navigation").toggleClass("active");
  return false;
};

// Amazon Associates referral code
function addReferralIds() {
  let referralId = Sugar.Configuration.amazonAssociatesId;
  let ptrn = /https?:\/\/([\w\d\-.])*(amazon|junglee)(\.com?)*\.([\w]{2,3})\//;

  let needsReferral = function (link) {
    return (
      !$.data(link, "amazon_associates_referral_id") &&
      link.href.match(ptrn)
    );
  };

  if (referralId) {
    $(".post .body a").each(function () {
      let link = this;
      if (needsReferral(link)) {
        $.data(link, "amazon_associates_referral_id", referralId);
        if (link.href.match(/(\?|&)tag=/)) {
          return;
        }

        link.href += link.href.match(/\?/) ? "&" : "?";
        link.href += "tag=" + referralId;
      }
    });
  }
}

function wrapEmbeds() {
  let selectors = [ "iframe[src*=\"bandcamp.com\"]",
                    "iframe[src*=\"player.vimeo.com\"]",
                    "iframe[src*=\"youtube.com\"]",
                    "iframe[src*=\"youtube-nocookie.com\"]",
                    "iframe[src*=\"kickstarter.com\"][src*=\"video.html\"]" ];

  let embeds = Array.prototype.slice.call(
    document.querySelectorAll(selectors.join(","))
  );

  function wrapEmbed(embed) {
    let wrapper = document.createElement("div");
    embed.parentNode.replaceChild(wrapper, embed);
    wrapper.appendChild(embed);
    return wrapper;
  }

  embeds.filter(e => !e.parentNode.classList.contains("responsive-embed"))
        .forEach(function (embed) {
          let width = embed.offsetWidth;
          let height = embed.offsetHeight;
          let ratio = height / width;
          let wrapper = wrapEmbed(embed);

          wrapper.classList.add("responsive-embed");
          wrapper.style.position = "relative";
          wrapper.style.width = "100%";
          wrapper.style.paddingBottom = (ratio * 100) + "%";

          embed.style.position = "absolute";
          embed.style.width = "100%";
          embed.style.height = "100%";
          embed.style.top = "0";
          embed.style.left = "0";
        });
}

$(document).ready(function () {
  let updateLayout = function () {
    if ((window.orientation != null)) {
      if (window.orientation === 90 || window.orientation === -90) {
        document.body.setAttribute("orient", "landscape");
      } else {
        document.body.setAttribute("orient", "portrait");
      }
    }
  };

  $(window).bind("orientationchange", updateLayout);
  $(window).bind("resize", updateLayout);
  updateLayout();

  $(".toggle-navigation").click(function () {
    window.toggleNavigation();
  });

  // Open images when clicked
  $(".post .body img").click(function () {
    document.location = this.src;
  });

  // Larger click targets on discussion overview
  $(".discussions .discussion h2 a").each(function () {
    var url = this.href;
    $(this.parentNode.parentNode).click(function () {
      document.location = url;
    });
  });

  // Scroll past the Safari chrome
  if (!document.location.toString().match(/#/)) {
    setTimeout(scrollTo, 100, 0, 1);
  }

  // Search mode
  $("#search_mode").change(function () {
    this.parentNode.action = this.value;
  });

  // Post quoting
  $(".post .functions a.quote_post").click(function () {
    let stripWhitespace = function (string) {
      return string.replace(/^[\s]*/, "").replace(/[\s]*$/, "");
    };

    let post = $(this).closest(".post");
    let username = post.find(".post_info .username a").text();
    let permalink = post.find(".post_info .permalink")
                        .get()[0]
                        .href
                        .replace(/^https?:\/\/([\w\d.:-]*)/, "");

    var text = stripWhitespace(post.find(".body").text());
    var html = stripWhitespace(post.find(".body").html());

    // Hide spoilers
    text = text.replace(/class="spoiler revealed"/g, "class=\"spoiler\"");
    html = html.replace(/class="spoiler revealed"/g, "class=\"spoiler\"");

    $(Sugar).trigger("quote", {
      username: username,
      permalink: permalink,
      text: text,
      html: html
    });

    return false;
  });

  // Muted posts
  $(".post").each(function () {
    const userId = $(this).data("user_id");
    if (
      window.mutedUsers &&
      window.mutedUsers.indexOf(userId) !== -1) {

      const notice = document.createElement("div");
      const showLink = document.createElement("a");
      const username = this.querySelector(".username a").textContent;

      showLink.innerHTML = "Show";
      showLink.addEventListener("click", (evt) => {
        evt.preventDefault();
        this.classList.remove("muted");
      });

      notice.classList.add("muted-notice");
      notice.innerHTML = `This post by <strong>${username}</strong> has been muted. `;
      notice.appendChild(showLink);

      this.classList.add("muted");
      this.appendChild(notice);
    }
  });

  // Posting
  $("form.new_post").submit(function () {
    // let body = $(this).find("#compose-body");
    return true;
  });

  // Spoiler tags
  $(".spoiler").click(function () {
    $(this).toggleClass("revealed");
  });

  // Login
  $("section.login").each(function () {
    function forgotPassword() {
      $("#login").toggle();
      $("#password-reminder").toggle();
    }
    $("#password-reminder").hide();
    $(".forgot-password").click(forgotPassword);
  });

  // Confirm regular site
  $("a.regular_site").click(function () {
    return confirm(
      "Are you sure you want to navigate away from the mobile version?"
    );
  });

  addReferralIds();
  wrapEmbeds();
  Sugar.init();
});
