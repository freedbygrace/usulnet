// Theme initialization - must load synchronously before CSS to prevent FOUC
(function() {
	var theme = localStorage.getItem('usulnet-theme') || 'dark';
	var html = document.documentElement;
	html.classList.remove('dark', 'light');
	html.classList.add(theme);
})();
