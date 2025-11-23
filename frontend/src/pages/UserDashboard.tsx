import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { apiService } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TokenTimer } from '@/components/TokenTimer';
import { 
  Upload, 
  FileText, 
  LogOut, 
  FolderOpen,
  Activity,
  Download,
  FolderPlus,
  Loader2,
  Trash2,
  HardDrive,
} from 'lucide-react';
import { toast } from 'sonner';

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

interface LogEntry {
  username: string;
  action: string;
  timestamp: string;
}

export const UserDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [allFiles, setAllFiles] = useState<FileItem[]>([]);
  const [folders, setFolders] = useState<FolderItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedFolder, setSelectedFolder] = useState<string | undefined>(undefined);
  const [newFolderName, setNewFolderName] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [expandedFolder, setExpandedFolder] = useState<string | null>(null);
  const [freeDiskSpace, setFreeDiskSpace] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [data, folderData, logsData, diskData] = await Promise.all([
        apiService.getFiles(),
        apiService.getFolders(),
        apiService.getLogs(),
        apiService.getDiskSpace(),
      ]);
      console.log('All files from API:', data.files);
      console.log('All folders from API:', folderData.folders);

      const accessibleFolders = folderData.folders.filter(f => 
        f.created_by === user || f.visible_to.includes(user) || user === "admin"
      );
      const accessibleFiles = data.files.filter(f => 
        f.visible_to.includes(user) || f.uploaded_by === user || user === "admin"
      );

      setAllFiles(accessibleFiles);
      setFolders(accessibleFolders);
      setLogs(logsData.filter(log => log.username === user));
      setFreeDiskSpace(diskData.free_space_gb);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toast.error('Please select a file first');
      return;
    }
    if (!selectedFolder) {
      toast.error('Please select a folder');
      return;
    }

    // Check for duplicate filename in the selected folder
    const fileExists = allFiles.some(
      (file) => file.filename === selectedFile.name && file.folder === selectedFolder
    );
    if (fileExists) {
      toast.error(`A file with the name ${selectedFile.name} already exists. Rename the file before uploading.`);
      return;
    }

    try {
      setUploading(true);
      await apiService.uploadFile(selectedFile, selectedFolder, '');
      toast.success(`Uploaded ${selectedFile.name} successfully to ${selectedFolder}`);
      setSelectedFile(null);
      setSelectedFolder(undefined);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      loadData();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) {
      toast.error('Please enter a folder name');
      return;
    }

    try {
      await apiService.createFolder(newFolderName.trim(), [user, "admin"]);
      toast.success(`Folder "${newFolderName}" created successfully`);
      setNewFolderName('');
      loadData();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create folder');
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleDownload = async (fileId: string, filename: string) => {
    try {
      const blob = await apiService.downloadFile(fileId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success(`Downloaded ${filename}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Download failed');
    }
  };

  const handleDeleteFile = async (fileId: string, filename: string) => {
    if (!confirm(`Are you sure you want to delete file "${filename}"?`)) {
      return;
    }

    try {
      await apiService.deleteFile(fileId);
      toast.success(`File ${filename} deleted successfully`);
      loadData();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to delete file');
    }
  };

  const handleChooseFileClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const toggleFolder = (folderName: string) => {
    setExpandedFolder(expandedFolder === folderName ? null : folderName);
  };

  if (loading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center bg-cover bg-center"
        style={{
          backgroundImage: `linear-gradient(to bottom, rgba(15, 23, 42, 0.3), rgba(15, 23, 42, 0.5)), url(/usercloud.jpg)`
        }}
      >
        <div className="flex items-center gap-3">
          <Loader2 className="h-6 w-6 animate-spin text-white" />
          <span className="text-white">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div
      className="min-h-screen bg-cover bg-center"
      style={{
        backgroundImage: `linear-gradient(to bottom, rgba(15, 23, 42, 0.3), rgba(15, 23, 42, 0.5)), url(/usercloud.jpg)`
      }}
    >
      <header className="border-b border-gray-600 backdrop-blur-md bg-gray-800/40 sticky top-0 z-10 transition-all duration-300">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative inline-block group transition-transform duration-500 ease-in-out hover:scale-105 hover:rotate-1">
                <div className="absolute inset-0 rounded-full bg-gradient-to-br from-gray-300/40 to-gray-500/40 blur-2xl animate-pulse opacity-30 z-0" />
                <img
                  src="/logo.png"
                  alt="Logo"
                  className="relative z-10 mx-auto w-10 h-10 object-cover rounded-full brightness-90 transition duration-500 ease-in-out group-hover:brightness-100 group-hover:shadow-lg group-hover:shadow-gray-300/40"
                />
              </div>
              <div>
                <h1 className="text-xl font-semibold bg-gradient-to-r from-gray-300 to-white bg-clip-text text-transparent animate-text-glow hover:scale-105 transition-transform duration-300 ease-in-out hover:drop-shadow-[0_0_10px_rgba(255,255,255,0.4)]">
                  User Dashboard
                </h1>
                <p className="text-sm text-gray-300">Welcome back, {user}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <TokenTimer />
              <Button 
                variant="outline" 
                onClick={logout} 
                size="sm" 
                className="text-white border-gray-600 hover:bg-gray-600 hover:text-white transition-all duration-300 hover:scale-[1.02]"
              >
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="grid gap-4 md:grid-cols-4 mb-8">
          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl transition-all duration-300 text-center">
            <CardContent className="p-6">
              <div className="text-2xl font-bold text-white">{allFiles.length}</div>
              <p className="text-sm text-gray-300">Total Files</p>
            </CardContent>
          </Card>
          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl transition-all duration-300 text-center">
            <CardContent className="p-6">
              <div className="text-2xl font-bold text-white">{folders.length}</div>
              <p className="text-sm text-gray-300">Your Folders</p>
            </CardContent>
          </Card>
          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl transition-all duration-300 text-center">
            <CardContent className="p-6">
              <div className="text-2xl font-bold text-white">{logs.length}</div>
              <p className="text-sm text-gray-300">Total Actions</p>
            </CardContent>
          </Card>
          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl transition-all duration-300 text-center">
            <CardContent className="p-6">
              <div className="text-2xl font-bold text-white">
                {freeDiskSpace !== null ? `${freeDiskSpace} GB` : 'N/A'}
              </div>
              <p className="text-sm text-gray-300">Free Disk Space</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl animate-slide-up transition-all duration-300">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Upload className="h-5 w-5 text-white" />
                <CardTitle className="text-white">Upload Files</CardTitle>
              </div>
              <CardDescription className="text-gray-300">
                Upload files to a folder in your secure repository (always visible to you and admin)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-4">
                <div>
                  <Label htmlFor="folder-select" className="text-gray-300">Select Folder</Label>
                  <Select onValueChange={setSelectedFolder} value={selectedFolder || undefined}>
                    <SelectTrigger id="folder-select" className="bg-gray-700 border-gray-600 text-white">
                      <SelectValue placeholder="Select a folder" />
                    </SelectTrigger>
                    <SelectContent className="bg-gray-700 border-gray-600 text-white">
                      {folders.length === 0 ? (
                        <SelectItem value="none" disabled>
                          No folders available
                        </SelectItem>
                      ) : (
                        folders.map((folder) => (
                          <SelectItem key={folder.id} value={folder.folder_name}>
                            {folder.folder_name}
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                </div>
                <div
                  className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors ${
                    dragActive 
                      ? 'border-white bg-white/10' 
                      : 'border-gray-600 hover:border-gray-500'
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  <Upload className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p className="text-sm text-gray-300 mb-2">
                    Drag and drop a file here, or click to select
                  </p>
                  <Input
                    type="file"
                    onChange={handleFileSelect}
                    className="hidden"
                    id="file-upload"
                    ref={fileInputRef}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleChooseFileClick}
                    className="text-white border-gray-600 hover:bg-gray-600 hover:text-white transition-all duration-300 hover:scale-[1.02]"
                  >
                    Choose File
                  </Button>
                </div>
              </div>
              
              {selectedFile && (
                <div className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg transition-all duration-300">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-gray-300" />
                    <span className="text-sm font-medium text-white">{selectedFile.name}</span>
                  </div>
                  <Button
                    onClick={handleUpload}
                    disabled={uploading || !selectedFolder}
                    size="sm"
                    className="ml-2 bg-gray-500 hover:bg-gray-600 text-white transition-all duration-300 hover:scale-[1.02]"
                  >
                    {uploading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      'Upload'
                    )}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl animate-slide-up transition-all duration-300" style={{ animationDelay: '0.1s' }}>
            <CardHeader>
              <div className="flex items-center gap-2">
                <FolderOpen className="h-5 w-5 text-white" />
                <CardTitle className="text-white">Your Folder Management</CardTitle>
              </div>
              <CardDescription className="text-gray-300">
                Create and view folders (visibility controlled by admin, always visible to you and admin)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    value={newFolderName}
                    onChange={(e) => setNewFolderName(e.target.value)}
                    placeholder="Enter folder name"
                    className="bg-gray-700 border-gray-600 text-white"
                  />
                  <Button
                    onClick={handleCreateFolder}
                    className="bg-gray-500 hover:bg-gray-600 text-white"
                  >
                    <FolderPlus className="h-4 w-4 mr-2" />
                    Create Folder
                  </Button>
                </div>
                {folders.length === 0 ? (
                  <div className="text-center py-8 text-gray-300">
                    <FolderOpen className="h-12 w-12 mx-auto mb-3 opacity-50" />
                    <p>No folders created or shared yet</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {folders.map((folder) => (
                      <div key={folder.id}>
                        <div className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg cursor-pointer transition-all duration-300 hover:bg-gray-600/50">
                          <div 
                            className="flex items-center gap-3 flex-grow"
                            onClick={() => toggleFolder(folder.folder_name)}
                          >
                            <FolderOpen className="h-4 w-4 text-gray-300" />
                            <span className="font-medium text-white">
                              {folder.created_by === user ? 'Created by You' : `Shared by ${folder.created_by}`}
                            </span>
                            <span className="text-sm text-gray-300"> - {folder.folder_name}</span>
                          </div>
                        </div>
                        {expandedFolder === folder.folder_name && (
                          <div className="ml-6 mt-2 space-y-2">
                            <div>
                              <Label className="text-gray-300">Visible To</Label>
                              <div className="p-4 bg-gray-700/50 rounded-lg">
                                <p className="text-sm text-gray-300">
                                  {folder.visible_to.join(', ')} {folder.visible_to.length === 0 ? 'Only you and admin' : '(always visible to you and admin)'}
                                </p>
                              </div>
                            </div>
                            {allFiles
                              .filter(f => f.folder === folder.folder_name && (f.visible_to.includes(user) || user === "admin"))
                              .map((file) => (
                                <div
                                  key={file.id}
                                  className="flex items-center justify-between p-3 bg-gray-600/50 rounded-lg transition-all duration-300"
                                >
                                  <div className="flex items-center gap-3">
                                    <FileText className="h-4 w-4 text-gray-300" />
                                    <span className="font-medium text-white">{file.filename}</span>
                                  </div>
                                  <div className="flex gap-2">
                                    <Button
                                      onClick={() => handleDownload(file.id, file.filename)}
                                      size="sm"
                                      variant="outline"
                                      className="text-white border-gray-600 hover:bg-gray-600 hover:text-white transition-all duration-300 hover:scale-[1.02]"
                                    >
                                      <Download className="h-4 w-4" />
                                    </Button>
                                    {file.uploaded_by === user && (
                                      <Button
                                        onClick={() => handleDeleteFile(file.id, file.filename)}
                                        size="sm"
                                        variant="destructive"
                                        className="bg-red-500 hover:bg-red-600 transition-all duration-300 hover:scale-[1.02]"
                                      >
                                        <Trash2 className="h-4 w-4" />
                                      </Button>
                                    )}
                                  </div>
                                </div>
                              ))}
                            {allFiles.filter(f => f.folder === folder.folder_name).length === 0 && (
                              <div className="text-center py-2 text-gray-300">
                                No files in this folder
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="backdrop-blur-md bg-gray-800/40 border-gray-600 shadow-xl rounded-2xl animate-slide-up transition-all duration-300" style={{ animationDelay: '0.2s' }}>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-white" />
                <CardTitle className="text-white">Your Activity Logs</CardTitle>
              </div>
              <CardDescription className="text-gray-300">
                Your actions logged in the system
              </CardDescription>
            </CardHeader>
            <CardContent>
              {logs.length === 0 ? (
                <div className="text-center py-8 text-gray-300">
                  <Activity className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No logs recorded yet</p>
                </div>
              ) : (
                <div className="space-y-3 max-h-72 overflow-y-auto">
                  {logs
                    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
                    .map((log, index) => (
                      <div
                        key={index}
                        className="p-3 bg-gray-700/50 rounded-lg flex justify-between items-start transition-all duration-300 hover:bg-gray-600/50"
                      >
                        <div>
                          <p className="text-sm">
                            <span className="font-medium text-white">{log.username}</span> - {log.action}
                          </p>
                          <p className="text-xs text-gray-300">
                            {new Date(log.timestamp).toLocaleString('en-GB', {
                              timeZone: 'Asia/Karachi',
                              year: 'numeric',
                              month: '2-digit',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit',
                              hour12: false,
                            })}
                          </p>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};