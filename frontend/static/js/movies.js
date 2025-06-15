// Функция для показа/скрытия индикатора загрузки
function setLoading(isLoading) {
    const loadingOverlay = document.getElementById('loading-overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = isLoading ? 'flex' : 'none';
    }
}

// Глобальная функция для обработки ошибок загрузки изображения
window.handleImageError = function(img) {
    console.error('Failed to load image:', img.src);
    img.src = '../static/images/no-poster.jpg';
};

// Глобальная функция для перехода на страницу деталей фильма
window.goToMovieDetails = function(movieId) {
    window.location.href = `movie-details.html?id=${movieId}`;
};

// Функция для обновления навигации
function updateNavigation() {
    const navLinks = document.getElementById('navLinks');
    const userData = JSON.parse(localStorage.getItem('userData'));
    const token = localStorage.getItem('access_token');

    if (userData && token) {
        // Пользователь авторизован
        navLinks.innerHTML = `
            <a href="profile.html" class="nav-link">
                <i class="fas fa-user"></i>
                ${userData.username}
            </a>
        `;
    } else {
        // Пользователь не авторизован
        navLinks.innerHTML = `
            <a href="auth.html" class="nav-link">
                <i class="fas fa-sign-in-alt"></i>
                Войти
            </a>
            <a href="register.html" class="nav-link">
                <i class="fas fa-user-plus"></i>
                Регистрация
            </a>
        `;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Обновляем навигацию при загрузке страницы
    updateNavigation();

    const moviesGrid = document.getElementById('moviesGrid');
    const searchInput = document.getElementById('searchInput');
    const genreFilter = document.getElementById('genreFilter');
    const yearFilter = document.getElementById('yearFilter');
    
    let allMovies = [];
    let filteredMovies = [];

    // Функция для получения правильного пути к изображению
    function getImagePath(posterPath) {
        console.log('Original poster_path:', posterPath);
        if (!posterPath) {
            console.log('No poster path, using placeholder');
            return '../static/images/no-poster.jpg';
        }
        
        // Извлекаем имя файла из полного пути
        const fileName = posterPath.split('\\').pop();
        // Используем относительный путь от текущей страницы
        const imagePath = `../static/images/${fileName}.jpg`;
        console.log('Generated image path:', imagePath);
        return imagePath;
    }

    // Загрузка фильмов
    async function loadMovies() {
        setLoading(true);
        try {
            console.log('Attempting to fetch movies...');
            const response = await fetch('http://localhost:8000/movies', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                mode: 'cors'
            });
            
            console.log('Response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Received data:', data);
            
            // Проверяем, что data - это массив
            if (!Array.isArray(data)) {
                throw new Error('Received data is not an array');
            }
            
            allMovies = data;
            filteredMovies = [...allMovies];
            displayMovies();
            setupFilters();
        } catch (error) {
            console.error('Error loading movies:', error);
            console.error('Error details:', {
                message: error.message,
                stack: error.stack
            });
            moviesGrid.innerHTML = `
                <div class="error-message">
                    <p>Ошибка при загрузке фильмов</p>
                    <p>Проверьте, что сервер запущен на http://localhost:8000</p>
                    <p>Детали ошибки: ${error.message}</p>
                </div>
            `;
        } finally {
            setLoading(false);
        }
    }

    // Отображение фильмов
    function displayMovies() {
        if (!Array.isArray(filteredMovies)) {
            console.error('filteredMovies is not an array:', filteredMovies);
            moviesGrid.innerHTML = '<p>Ошибка: данные фильмов неверного формата</p>';
            return;
        }

        if (filteredMovies.length === 0) {
            moviesGrid.innerHTML = '<p>Фильмы не найдены</p>';
            return;
        }

        moviesGrid.innerHTML = filteredMovies.map(movie => {
            const imagePath = getImagePath(movie.poster_path);
            console.log(`Movie ${movie.title} image path:`, imagePath);
            return `
                <div class="movie-card" onclick="goToMovieDetails(${movie.id})">
                    <img src="${imagePath}" 
                         alt="${movie.title}"
                         onerror="handleImageError(this)"
                         onload="console.log('Image loaded successfully:', this.src)">
                    <div class="movie-info">
                        <h3 class="movie-title">${movie.title}</h3>
                        <p class="movie-year">${movie.year}</p>
                        <p class="movie-rating">★ ${movie.rating.toFixed(1)}</p>
                    </div>
                </div>
            `;
        }).join('');
    }

    // Настройка фильтров
    function setupFilters() {
        if (!Array.isArray(allMovies)) {
            console.error('allMovies is not an array:', allMovies);
            return;
        }

        // Получаем уникальные жанры
        const genres = [...new Set(allMovies.flatMap(movie => movie.genres || []))];
        const genreFilter = document.getElementById('genreFilter');
        
        // Добавляем опции для жанров
        genres.forEach(genre => {
            const option = document.createElement('option');
            option.value = genre;
            option.textContent = genre;
            genreFilter.appendChild(option);
        });
        
        // Получаем уникальные годы
        const years = [...new Set(allMovies.map(movie => movie.year))].sort((a, b) => b - a);
        const yearFilter = document.getElementById('yearFilter');
        
        // Добавляем опции для годов
        years.forEach(year => {
            const option = document.createElement('option');
            option.value = year;
            option.textContent = year;
            yearFilter.appendChild(option);
        });
        
        // Добавляем обработчики событий для фильтров
        document.getElementById('searchInput').addEventListener('input', applyFilters);
        genreFilter.addEventListener('change', applyFilters);
        yearFilter.addEventListener('change', applyFilters);
    }

    // Применение фильтров
    function applyFilters() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const selectedGenre = document.getElementById('genreFilter').value;
        const selectedYear = document.getElementById('yearFilter').value;
        
        filteredMovies = allMovies.filter(movie => {
            const matchesSearch = movie.title.toLowerCase().includes(searchTerm);
            const matchesGenre = !selectedGenre || (movie.genres && movie.genres.includes(selectedGenre));
            const matchesYear = !selectedYear || movie.year.toString() === selectedYear;
            
            return matchesSearch && matchesGenre && matchesYear;
        });
        
        displayMovies();
    }

    // Загрузка фильмов при загрузке страницы
    loadMovies();
}); 