document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('toggle-sidebar-btn');
    const footer = document.querySelector('.footer');

    // Toggle sidebar visibility
    toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        footer.classList.toggle('open');
    });

    // Update footer year dynamically
    const yearSpan = document.getElementById('current-year');
    yearSpan.textContent = new Date().getFullYear();
});
