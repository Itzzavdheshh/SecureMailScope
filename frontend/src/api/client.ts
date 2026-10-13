import axios from 'axios';

// Create central Axios client
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor for consistent error extraction
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    let message: string | undefined;

    const data = error.response?.data;
    if (data) {
      if (typeof data.detail === 'string') {
        message = data.detail;
      } else if (data.detail && typeof data.detail === 'object') {
        if (typeof data.detail.message === 'string') {
          message = data.detail.message;
        } else if (Array.isArray(data.detail)) {
          message = data.detail
            .map((item: any) => {
              if (typeof item === 'string') return item;
              if (item && typeof item === 'object') {
                const field = Array.isArray(item.loc) && item.loc.length > 1 ? `${item.loc[item.loc.length - 1]}: ` : '';
                return `${field}${item.msg || JSON.stringify(item)}`;
              }
              return String(item);
            })
            .join('; ');
        } else {
          try {
            message = JSON.stringify(data.detail);
          } catch {
            message = 'An unexpected error occurred';
          }
        }
      } else if (typeof data.message === 'string') {
        message = data.message;
      } else if (typeof data.error?.message === 'string') {
        message = data.error.message;
      }
    }

    if (!message || message === '[object Object]') {
      message = (error.message && error.message !== '[object Object]') ? error.message : 'An unexpected network error occurred';
    }

    const customErr = new Error(message);
    (customErr as any).response = error.response;
    return Promise.reject(customErr);
  }
);
