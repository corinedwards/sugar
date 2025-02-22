import Backbone from "backbone";

export default Backbone.Model.extend({
  paramRoot: "user",
  idAttribute: "id",

  defaults: {
    username: "",
    admin: false,
    moderator: false,
    user_admin: false
  },

  urlRoot: function () {
    return "/users";
  },

  isAdmin: function () {
    return this.get("admin");
  },

  isModerator: function () {
    return this.get("moderator") || this.isAdmin();
  },

  isUserAdmin: function () {
    return this.get("user_admin") || this.isAdmin();
  }
});
