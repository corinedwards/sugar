import $ from "jquery";
import Sugar from "../../sugar";

require("../../vendor/jquery.autocomplete");

$(Sugar).bind("ready", function() {
  $("#invite_participant_form").each(function() {
    var $inputField = $(this).find(".username");

    var usernames = [];

    // Set up autocompletion
    $inputField.autocomplete([], {
      autoFill: true,
      width:    200,
      data:     usernames
    });

    // Load usernames from the backend on focus
    $inputField.focus(function() {
      if (usernames.length === 0) {
        return $.getJSON("/users.json", function(json) {
          usernames = ((() => {
            var result = [];
            for (var i = 0, user; i < json.data.length; i++) {
              user = json.data[i];
              result.push(user.attributes.username);
            }
            return result;
          })());
          $inputField.setOptions({data: usernames});
        });
      }
    });

    // Submit via AJAX and update the list
    $(this).submit(function() {
      $("#sidebar .participants ul").fadeTo("fast", 0.8);

      var data = {
        username:           $inputField.val(),
        authenticity_token: Sugar.authToken()
      };

      $.post(this.action, data, function(response) {
        $("#sidebar .participants").html(response);
        $("#sidebar .participants ul").fadeTo(0, 0.8).fadeTo("fast", 1.0);
      });

      $inputField.val("");
      return false;
    });
  });
});
