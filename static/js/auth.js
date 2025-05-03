// Show Pass
function showPass() {
    const passwordInput = document.getElementById("password");
    const passwordType = passwordInput.type;

    if (passwordType === "password") {
        passwordInput.type = "text";
        document.getElementById("showPass").innerHTML = '<i class="fa-regular fa-eye"></i>';
    } else {
        passwordInput.type = "password";
        document.getElementById("showPass").innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
    }
}

function showPass2() {
    const passwordInput = document.getElementById("confirm_password");
    const passwordType = passwordInput.type;

    if (passwordType === "password") {
        passwordInput.type = "text";
        document.getElementById("showPass2").innerHTML = '<i class="fa-regular fa-eye"></i>';
    } else {
        passwordInput.type = "password";
        document.getElementById("showPass2").innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
    }
}