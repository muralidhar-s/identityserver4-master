$(document).ready(function () {
    $("#countries").msDropdown({
        initialCountryIndex: $("#CountryIndex").val(),
        initialCountryCode: $("#CountryCode").val(),
        change: function (data) {
            $("#CountryCode").val(data);
            updateLogos(data);
        }
    });
});

function updateLogos(data) {
    if (data === "US") {
        $("#humanId").show();
        $("#bluenumberId").hide();
        $("#btnHumanId").show();
        $("#btnBlunumberId").hide();
    } else {
        $("#humanId").hide();
        $("#bluenumberId").show();
        $("#btnHumanId").hide();
        $("#btnBlunumberId").show();
    }
}