import Backbone from "backbone";
import $ from "jquery";
import Sugar from "../sugar";
import Posts from "./Posts";

export default Backbone.View.extend({
  el: $("body"),

  initialize: function () {
    let postsSelector = "body.discussion div.posts, " +
                        "body.search div.posts, " +
                        "body.user_profile div.posts";
    $(postsSelector).each(function() {
      this.view = new Posts({
        el: this
      });
    });
    $(Sugar).trigger("ready");
  }
});
