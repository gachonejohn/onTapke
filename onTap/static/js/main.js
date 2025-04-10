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
