document.addEventListener('DOMContentLoaded', function() {
    const statNumbers = document.querySelectorAll('.stat-number');
    
    
    const animationDuration = 1000;
    
    // Function to animate counting
    function animateValue(element, start, end, duration) {
      
      const plusSpan = element.querySelector('span');
      if (plusSpan) {
        element.removeChild(plusSpan);
      }
      
      let startTimestamp = null;
      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const currentValue = Math.floor(progress * (end - start) + start);
        element.textContent = currentValue;
        
        // Add the plus span back
        if (plusSpan && progress === 1) {
          element.appendChild(plusSpan);
        }
        
        if (progress < 1) {
          window.requestAnimationFrame(step);
        }
      };
      
      window.requestAnimationFrame(step);
    }
    
    
    function isInViewport(element) {
      const rect = element.getBoundingClientRect();
      return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
      );
    }
    
  
    function handleScroll() {
      statNumbers.forEach(statNumber => {
        if (statNumber.dataset.animated === 'true') return;
        
        if (isInViewport(statNumber)) {
          const targetNumber = parseInt(statNumber.textContent);
          statNumber.dataset.animated = 'true';
          animateValue(statNumber, 0, targetNumber, animationDuration);
        }
      });
    }
    
    
    handleScroll();
    window.addEventListener('scroll', handleScroll);
  });
 


  // Custom toggle icon handling
  document.querySelectorAll('.card-header').forEach(header => {
      header.addEventListener('click', () => {
          const toggleIcon = header.querySelector('.toggle-icon');
          const isExpanded = header.getAttribute('aria-expanded') === 'true';
          toggleIcon.textContent = isExpanded ? '+' : '−';
          header.setAttribute('aria-expanded', !isExpanded);
      });
  });




  document.addEventListener('DOMContentLoaded', function() {
    const carousel = new bootstrap.Carousel(document.getElementById('heroCarousel'), {
        interval: 5000,
        ride: true,
        wrap: true
    });
    
    // Re-trigger animations when slide changes
    document.getElementById('heroCarousel').addEventListener('slide.bs.carousel', function () {
        const title = document.querySelector('.animate-title');
        const subtitle = document.querySelector('.animate-subtitle');
        const btn1 = document.querySelector('.animate-btn-1');
        const btn2 = document.querySelector('.animate-btn-2');
        
        // Reset animations
        title.style.animation = 'none';
        subtitle.style.animation = 'none';
        btn1.style.animation = 'none';
        btn2.style.animation = 'none';
        
        // Trigger reflow to restart animations
        void title.offsetWidth;
        void subtitle.offsetWidth;
        void btn1.offsetWidth;
        void btn2.offsetWidth;
        
        // Restart animations
        title.style.animation = 'fadeInUp 0.8s ease forwards';
        subtitle.style.animation = 'fadeInUp 0.8s ease 0.3s forwards';
        btn1.style.animation = 'fadeInUp 0.8s ease 0.6s forwards';
        btn2.style.animation = 'fadeInUp 0.8s ease 0.8s forwards';
    });
});





  document.addEventListener('DOMContentLoaded', function() {
    const monthlyBtn = document.getElementById('monthly-btn');
    const yearlyBtn = document.getElementById('yearly-btn');
    const monthlyPrices = document.querySelectorAll('.monthly-price');
    const yearlyPrices = document.querySelectorAll('.yearly-price');
    const monthlyCycles = document.querySelectorAll('.monthly-cycle');
    const yearlyCycles = document.querySelectorAll('.yearly-cycle');

    monthlyBtn.addEventListener('click', function() {
      monthlyBtn.classList.add('active');
      yearlyBtn.classList.remove('active');
      
      // Show monthly prices, hide yearly prices
      monthlyPrices.forEach(price => price.style.display = 'inline');
      yearlyPrices.forEach(price => price.style.display = 'none');
      monthlyCycles.forEach(cycle => cycle.style.display = 'inline');
      yearlyCycles.forEach(cycle => cycle.style.display = 'none');
    });

    yearlyBtn.addEventListener('click', function() {
      yearlyBtn.classList.add('active');
      monthlyBtn.classList.remove('active');
      
      // Show yearly prices, hide monthly prices
      monthlyPrices.forEach(price => price.style.display = 'none');
      yearlyPrices.forEach(price => price.style.display = 'inline');
      monthlyCycles.forEach(cycle => cycle.style.display = 'none');
      yearlyCycles.forEach(cycle => cycle.style.display = 'inline');
    });
  });









