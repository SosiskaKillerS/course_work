document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('access_token');
    const navLinks = document.getElementById('navLinks');
    
    if (!token) {
        navLinks.innerHTML = `
            <a href="auth.html" class="nav-link">
                <i class="fas fa-sign-in-alt"></i>
                Войти
            </a>
            <a href="auth.html" class="nav-link">
                <i class="fas fa-user-plus"></i>
                Регистрация
            </a>
        `;
        document.getElementById('movie-details').innerHTML = `
            <div class="unauthorized-message">
                <i class="fas fa-lock"></i>
                <h2>Требуется авторизация</h2>
                <p>Для просмотра деталей фильма необходимо войти в систему</p>
                <a href="auth.html" class="auth-button">Войти</a>
            </div>
        `;
        return;
    }

    // Получаем ID фильма из URL
    const urlParams = new URLSearchParams(window.location.search);
    const movieId = urlParams.get('id');
    
    if (!movieId) {
        document.getElementById('movie-details').innerHTML = '<p>Фильм не найден</p>';
        return;
    }

    // Загружаем информацию о фильме
    fetch(`http://localhost:8000/movies/${movieId}`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.json())
    .then(movie => {
        document.getElementById('movie-details').innerHTML = `
            <div class="movie-details-container">
                <div class="movie-poster">
                    <img src="${movie.poster_path}" alt="${movie.title}">
                </div>
                <div class="movie-info">
                    <h1>${movie.title}</h1>
                    <div class="movie-meta">
                        <span class="movie-year">${movie.year}</span>
                        <span class="movie-rating">${movie.rating.toFixed(1)}</span>
                    </div>
                    <div class="movie-description">
                        <h2>Описание</h2>
                        <p>${movie.description}</p>
                    </div>
                    <div class="movie-genres">
                        <h2>Жанры</h2>
                        <div class="genre-tags">
                            ${movie.genres.map(genre => `
                                <span class="genre-tag">${genre.name}</span>
                            `).join('')}
                        </div>
                    </div>
                    <div class="movie-directors">
                        <h2>Режиссеры</h2>
                        <ul>
                            ${movie.directors.map(director => `
                                <li>${director.name}</li>
                            `).join('')}
                        </ul>
                    </div>
                    <div class="movie-actors">
                        <h2>Актеры</h2>
                        <ul>
                            ${movie.actors.map(actor => `
                                <li>${actor.name}</li>
                            `).join('')}
                        </ul>
                    </div>
                </div>
            </div>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('movie-details').innerHTML = '<p>Ошибка при загрузке информации о фильме</p>';
    });
}); 