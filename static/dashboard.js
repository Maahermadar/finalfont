document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const sidebar = document.querySelector('.sidebar');
  const toggleBtn = document.querySelector('.toggle-btn');
  const searchInput = document.querySelector('.search-input');
  const navLinks = document.querySelectorAll('.nav-link');
  const logoutBtn = document.querySelector('.logout-btn');
  
  // Set tooltip attributes for collapsed state
  navLinks.forEach(link => {
    link.setAttribute('data-tooltip', link.querySelector('span').textContent);
  });
  
  if (logoutBtn) {
    logoutBtn.setAttribute('data-tooltip', 'Logout');
  }

  // Toggle sidebar
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', function() {
      sidebar.classList.toggle('collapsed');
      
      // Store preference in localStorage
      const isCollapsed = sidebar.classList.contains('collapsed');
      localStorage.setItem('sidebarCollapsed', isCollapsed);
    });
  }

  // Search functionality
  if (searchInput && navLinks) {
    searchInput.addEventListener('input', function() {
      const searchTerm = this.value.toLowerCase();
      
      navLinks.forEach(link => {
        const linkText = link.textContent.toLowerCase();
        const navItem = link.closest('.nav-link');
        
        if (linkText.includes(searchTerm)) {
          navItem.style.display = 'flex';
        } else {
          navItem.style.display = 'none';
        }
      });
    });
  }

  // Check for saved sidebar state
  function checkSidebarState() {
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    
    // Responsive behavior - collapse on mobile by default
    if (window.innerWidth < 992) {
      sidebar.classList.add('collapsed');
    } else {
      if (isCollapsed) {
        sidebar.classList.add('collapsed');
      } else {
        sidebar.classList.remove('collapsed');
      }
    }
  }

  // Initialize
  checkSidebarState();
  
  // Handle window resize
  window.addEventListener('resize', function() {
    checkSidebarState();
  });

  // Close sidebar when clicking outside on mobile
  document.addEventListener('click', function(e) {
    if (window.innerWidth < 992 && !sidebar.contains(e.target) {
      sidebar.classList.add('collapsed');
    }
  });
});