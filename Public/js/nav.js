 
        const burger = document.getElementById('burger');
        const navLinks = document.getElementById('navLinks');
        const mainContent = document.querySelector('main');

        burger.addEventListener('click', () => {
            navLinks.classList.toggle('show');
            document.body.classList.toggle('menu-open');
            burger.textContent = navLinks.classList.contains('show') ? '✕' : '☰';
            
            if (navLinks.classList.contains('show')) {
                setTimeout(() => {
                    mainContent.style.visibility = 'hidden';
                }, 300);
            } else {
                mainContent.style.visibility = 'visible';
            }
        });

        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });