function moveCursor(fromTextBox, toTextBox)
{
    var length = fromTextBox.value.length;
    var maxLength = fromTextBox.getAttribute("maxlength");

    if(length == maxLength)
    {
        document.getElementById(toTextBox).focus();
    }
}