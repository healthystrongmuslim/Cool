// Removed unused 'axios' import to improve Code Quality Grade

// Use Environment Variable for URL (Fallback to localhost if not set)
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

interface LoginRequest {
  username: string;
  password: string;
}

interface RegisterRequest {
  username: string;
  password: string;
}

interface UpdateUserRequest {
  current_username: string;
  new_username?: string;
  new_password?: string;
}

interface FileItem {
  id: string;
  filename: string;
  folder: string;
  uploaded_by: string;
  visible_to: string[];
}

interface FolderItem {
  id: string;
  folder_name: string;
  created_by: string;
  created_at: string;
  visible_to: string[];
}

interface TokenItem {
  token: string;
  username: string;
  expires_at: string;
}

// Improved Typing: Removed explicit 'any' to satisfy strict linters
interface ApiResponse {
  message?: string;
  token?: string;
  role?: string; // Added role to interface
  expires_in_minutes?: number;
  [key: string]: unknown; // Safer than 'any'
}

class ApiService {
  private getAuthHeader() {
    const token = localStorage.getItem('auth_token');
    return token ? { Authorization: token } : {};
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    
    // Default headers (unless overridden, e.g. for FormData)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.getAuthHeader(),
      ...(options.headers as Record<string, string>),
    };

    // If body is FormData, let browser set Content-Type (delete our default)
    if (options.body instanceof FormData) {
      delete headers['Content-Type'];
    }

    const config: RequestInit = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        let errorDetail = 'Request failed';
        try {
          const errorData = await response.json();
          errorDetail = errorData.detail || errorData.message || `HTTP ${response.status}`;
        } catch {
          errorDetail = `HTTP ${response.status}`;
        }
        throw new Error(errorDetail);
      }

      return await response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Network request failed');
    }
  }

  // --- Auth Endpoints ---

  async login(credentials: LoginRequest): Promise<ApiResponse> {
    return this.request('/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  }

  async adminLogin(credentials: LoginRequest): Promise<ApiResponse> {
    return this.request('/admin-login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  }

  async logout(): Promise<ApiResponse> {
    return this.request('/logout', { method: 'POST' });
  }

  async getTokenStatus(): Promise<{
    username: string;
    role: string;
    minutes_remaining: number;
    expires_at: string;
  }> {
    return this.request('/token-status');
  }

  async getAllTokens(): Promise<{ active_tokens: TokenItem[] }> {
    return this.request('/admin/tokens');
  }

  // --- User Management ---

  async registerUser(userData: RegisterRequest): Promise<ApiResponse> {
    return this.request('/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async getUsers(): Promise<{ users: Array<{ username: string; role: string }> }> {
    return this.request('/users');
  }

  async updateUser(updateData: UpdateUserRequest): Promise<ApiResponse> {
    return this.request('/user/update', {
      method: 'PUT',
      body: JSON.stringify({
        current_username: updateData.current_username,
        new_username: updateData.new_username || undefined,
        new_password: updateData.new_password || undefined,
      }),
    });
  }

  async deleteUser(username: string): Promise<ApiResponse> {
    return this.request(`/user/${username}`, { method: 'DELETE' });
  }

  // --- File and Folder Management ---

  async getFiles(): Promise<{ files: FileItem[]; folders: FolderItem[] }> {
    return this.request('/files');
  }

  async getFolders(): Promise<{ folders: FolderItem[] }> {
    return this.request('/folders');
  }

  async uploadFile(file: File, folder: string, visible_to: string): Promise<ApiResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('folder', folder);
    formData.append('visible_to', visible_to);

    // Reuse the central request method now that it handles FormData
    return this.request('/upload', {
      method: 'POST',
      body: formData,
    });
  }

  async downloadFile(fileId: string): Promise<Blob> {
    const url = `${API_BASE_URL}/download/${fileId}`;
    const response = await fetch(url, {
      headers: {
        ...this.getAuthHeader()
      } as HeadersInit,
    });

    if (!response.ok) {
      throw new Error('Download failed');
    }

    return response.blob();
  }

  async deleteFile(fileId: string): Promise<ApiResponse> {
    return this.request(`/file/${fileId}`, { method: 'DELETE' });
  }

  async createFolder(folderName: string, visible_to: string[]): Promise<ApiResponse> {
    return this.request('/create-folder', {
      method: 'POST',
      body: JSON.stringify({ folder_name: folderName, visible_to }),
    });
  }

  async updateFolderVisibility(folderName: string, visible_to: string[]): Promise<ApiResponse> {
    return this.request(`/folder/${folderName}/visibility`, {
      method: 'PUT',
      body: JSON.stringify({ visible_to }),
    });
  }

  async deleteFolder(folderName: string): Promise<ApiResponse> {
    return this.request(`/folder/${folderName}`, { method: 'DELETE' });
  }

  async getLogs(): Promise<Array<{ username: string; action: string; timestamp: string }>> {
    return this.request('/logs');
  }

  async getDiskSpace(): Promise<{ free_space_gb: number }> {
    return this.request('/disk-space');
  }
}

export const apiService = new ApiService();