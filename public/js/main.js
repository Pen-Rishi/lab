// ============================================================
// AVENGERS ARMORY - Frontend Scripts
// Warning: Contains intentional XSS vulnerabilities!
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
  
  // ---- Mobile menu toggle ----
  const menuToggle = document.querySelector('.mobile-menu-toggle');
  const navLinks = document.querySelector('.nav-links');
  
  if (menuToggle) {
    menuToggle.addEventListener('click', function() {
      navLinks.classList.toggle('show');
    });
  }

  // ---- Quantity selectors ----
  document.querySelectorAll('.quantity-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const input = this.parentElement.querySelector('.quantity-input');
      if (!input) return;
      let val = parseInt(input.value) || 1;
      if (this.classList.contains('minus') && val > 1) val--;
      if (this.classList.contains('plus')) val++;
      input.value = val;
    });
  });

  // ---- Auto-dismiss alerts after 5 seconds ----
  document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 500);
    }, 5000);
  });

  // ---- Price formatting ----
  document.querySelectorAll('.format-price').forEach(el => {
    const price = parseFloat(el.dataset.price);
    if (!isNaN(price)) {
      el.textContent = `$${price.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }
  });

  // ---- Smooth scroll for anchor links ----
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const href = this.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });

  // ---- Cart add animation ----
  document.querySelectorAll('.add-to-cart-btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
      this.textContent = '✓ Added!';
      this.classList.remove('btn-primary');
      this.classList.add('btn-success');
      setTimeout(() => {
        this.textContent = 'Add to Cart';
        this.classList.remove('btn-success');
        this.classList.add('btn-primary');
      }, 1500);
    });
  });

  // ---- Sticky navbar on scroll ----
  let lastScrollTop = 0;
  const navbar = document.querySelector('.navbar');
  
  if (navbar) {
    window.addEventListener('scroll', function() {
      const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
      if (scrollTop > 100) {
        navbar.style.background = 'rgba(10, 10, 15, 0.98)';
      } else {
        navbar.style.background = 'rgba(10, 10, 15, 0.95)';
      }
      lastScrollTop = scrollTop;
    });
  }

  // ---- XSS Demo: URL parameter reflection ----
  const urlParams = new URLSearchParams(window.location.search);
  const xssMessage = urlParams.get('msg');
  // A03: Reflected XSS - directly injecting URL parameter
  if (xssMessage) {
    const xssContainer = document.getElementById('xss-output');
    if (xssContainer) {
      xssContainer.innerHTML = xssMessage;
    }
  }

  console.log('⚔️ Avengers Armory loaded! Earth\'s mightiest marketplace!');
});
