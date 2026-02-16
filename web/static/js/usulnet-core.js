// usulnet core JavaScript
// Provides: theme toggle, toast notifications, utility functions, HTMX lifecycle

window.usulnet = {
	toggleTheme: function() {
		var html = document.documentElement;
		var isDark = html.classList.contains('dark');
		var newTheme = isDark ? 'light' : 'dark';
		html.classList.remove('dark', 'light');
		html.classList.add(newTheme);
		localStorage.setItem('usulnet-theme', newTheme);
		var icon = document.getElementById('theme-toggle-icon');
		if (icon) {
			icon.className = 'fas ' + (newTheme === 'dark' ? 'fa-moon' : 'fa-sun');
		}
	},

	toast: function(message, type, duration) {
		if (!type) type = 'info';
		if (duration === undefined) duration = 4000;
		var container = document.getElementById('toast-container');
		if (!container) return;
		var toast = document.createElement('div');
		var colors = {
			success: 'bg-green-600 border-green-500',
			error: 'bg-red-600 border-red-500',
			warning: 'bg-yellow-600 border-yellow-500',
			info: 'bg-primary-600 border-primary-500'
		};
		var icons = {
			success: 'fa-check-circle',
			error: 'fa-exclamation-circle',
			warning: 'fa-exclamation-triangle',
			info: 'fa-info-circle'
		};
		toast.className = (colors[type] || colors.info) + ' text-white px-4 py-3 rounded-lg shadow-lg border-l-4 flex items-center gap-3 animate-slide-in max-w-sm';
		toast.setAttribute('role', 'alert');
		toast.innerHTML = '<i class="fas ' + (icons[type] || icons.info) + '" aria-hidden="true"></i>' +
			'<span class="flex-1 text-sm">' + message + '</span>' +
			'<button onclick="this.parentElement.remove()" class="text-white/70 hover:text-white ml-2" aria-label="Dismiss notification">' +
			'<i class="fas fa-times text-xs" aria-hidden="true"></i></button>';
		container.appendChild(toast);
		if (duration > 0) {
			setTimeout(function() { if (toast.parentElement) toast.remove(); }, duration);
		}
	},

	formatBytes: function(bytes, decimals) {
		if (decimals === undefined) decimals = 2;
		if (bytes === 0) return '0 B';
		var k = 1024;
		var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
		var i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
	}
};

// HTMX CSRF injection
document.addEventListener('htmx:configRequest', function(event) {
	var csrfMeta = document.querySelector('meta[name="csrf-token"]');
	if (csrfMeta) {
		event.detail.headers['X-CSRF-Token'] = csrfMeta.content;
	}
});

// HTMX lifecycle: toast parsing + error feedback
(function() {
	document.body.addEventListener('htmx:afterRequest', function(evt) {
		var xhr = evt.detail.xhr;
		if (xhr) {
			var trigger = xhr.getResponseHeader('HX-Trigger');
			if (trigger) {
				try {
					var data = JSON.parse(trigger);
					if (data.showToast) {
						usulnet.toast(data.showToast.message, data.showToast.type);
					}
				} catch (e) {}
			}
		}
	});

	document.body.addEventListener('htmx:responseError', function(evt) {
		var xhr = evt.detail.xhr;
		var status = xhr ? xhr.status : 0;
		var message = 'Request failed';
		switch (status) {
			case 401: message = 'Session expired - redirecting to login'; setTimeout(function() { window.location.href = '/login'; }, 1500); break;
			case 403: message = 'Permission denied'; break;
			case 404: message = 'Resource not found'; break;
			case 422: message = 'Validation error'; break;
			case 429: message = 'Too many requests - please wait'; break;
			case 500: message = 'Server error - please try again'; break;
			case 502: case 503: message = 'Service temporarily unavailable'; break;
			case 0: message = 'Network error - check your connection'; break;
		}
		usulnet.toast(message, 'error', 6000);
	});

	document.body.addEventListener('htmx:timeout', function() {
		usulnet.toast('Request timed out', 'warning', 6000);
	});

	document.body.addEventListener('htmx:sendError', function() {
		usulnet.toast('Connection error - check your network', 'error', 6000);
	});
})();
