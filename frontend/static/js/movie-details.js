document.addEventListener('DOMContentLoaded', () => {
    // Получаем ID фильма из URL
    const urlParams = new URLSearchParams(window.location.search);
    const movieId = urlParams.get('id');
    
    if (!movieId) {
        document.getElementById('movie-details').innerHTML = '<p>Фильм не найден</p>';
        return;
    }

    // Здесь будет загрузка данных фильма
    console.log('Movie ID:', movieId);
}); 