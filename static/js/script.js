window.addEventListener("scroll", function() {
    var navbar = document.querySelector(".navbar");
    if (window.scrollY > 1) {
        navbar.style.backgroundColor = "rgba(0, 0, 0, 0.7)";
        navbar.style.backdropFilter = "blur(2px)";
        navbar.style.borderBottom = "1px solid rgba(255, 255, 255, 0.2)";
    } else {
        navbar.style.backgroundColor = "transparent";
        navbar.style.backdropFilter = "none";
        navbar.style.borderBottom = "none";
    }
});

// Navbar Active
const menuItems = document.querySelectorAll('nav ul li a');

// jika nav items diclick
menuItems.forEach(item => {
    item.addEventListener('click', function () {
        // Menghapus kelas "active" dari semua elemen menu
        menuItems.forEach(item => {
            item.classList.remove('active');
        });

        // Menambahkan kelas "active" pada elemen menu yang diklik
        this.classList.add('active');
    });

});

const menuItemsHp = document.querySelectorAll('nav li a');

// jika nav items diclick
menuItemsHp.forEach(item => {
    item.addEventListener('click', function () {
        // Menghapus kelas "active" dari semua elemen menu
        menuItemsHp.forEach(item => {
            item.classList.remove('active');
        });

        // Menambahkan kelas "active" pada elemen menu yang diklik
        this.classList.add('active');
    });
});
// Navbar Active End