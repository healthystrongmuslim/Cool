import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ArrowLeft, UserPlus, Loader2 } from 'lucide-react';
import { toast } from 'sonner';

export const RegisterUser: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: '',
  });

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.username || !formData.password || !formData.confirmPassword) {
      toast.error('Please fill in all fields');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    if (formData.password.length < 3) {
      toast.error('Password must be at least 3 characters long');
      return;
    }

    try {
      setLoading(true);
      await apiService.registerUser({
        username: formData.username,
        password: formData.password,
      });
      toast.success(`User ${formData.username} registered successfully`);
      navigate('/dashboard');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center bg-cover bg-center"
      style={{
        backgroundImage: `linear-gradient(to bottom, rgba(15, 23, 42, 0.3), rgba(15, 23, 42, 0.5)), url(/cloudadmin.jpg)`,
      }}
    >
      <div className="w-full max-w-md animate-fade-in">
        <div className="text-center mb-8 relative">
          <div className="relative inline-block group transition-transform duration-500 ease-in-out hover:scale-105 hover:rotate-1">
            <div className="absolute inset-0 rounded-full bg-gradient-to-br from-gray-300/40 to-gray-500/40 blur-2xl animate-pulse opacity-30 z-0" />
            <img
              src="/logo.png"
              alt="Logo"
              className="relative z-10 mx-auto w-24 h-24 object-cover rounded-full brightness-90 transition duration-500 ease-in-out group-hover:brightness-100 group-hover:shadow-lg group-hover:shadow-gray-300/40"
            />
          </div>
          <h1 className="mt-4 text-3xl font-bold bg-gradient-to-r from-gray-300 to-white bg-clip-text text-transparent animate-text-glow hover:scale-105 transition-transform duration-300 ease-in-out hover:drop-shadow-[0_0_10px_rgba(255,255,255,0.4)]">
            Cool Cloud
          </h1>
        </div>

        <Card className="backdrop-blur-md bg-gray-800/40 border border-gray-600 shadow-xl rounded-2xl transition-all duration-300">
          <CardHeader className="text-center">
            <CardTitle className="text-white">Register New User</CardTitle>
            <CardDescription className="text-gray-300">
              Create a new user account for the system
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-gray-300">Username</Label>
                <Input
                  id="username"
                  type="text"
                  placeholder="Enter username"
                  value={formData.username}
                  onChange={(e) => handleInputChange('username', e.target.value)}
                  disabled={loading}
                  className="bg-gray-700 border-gray-600 text-white placeholder-gray-300 focus:border-gray-500 focus:ring-gray-500"
                  required
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="password" className="text-gray-300">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter password"
                  value={formData.password}
                  onChange={(e) => handleInputChange('password', e.target.value)}
                  disabled={loading}
                  className="bg-gray-700 border-gray-600 text-white placeholder-gray-300 focus:border-gray-500 focus:ring-gray-500"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-gray-300">Confirm Password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="Confirm password"
                  value={formData.confirmPassword}
                  onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                  disabled={loading}
                  className="bg-gray-700 border-gray-600 text-white placeholder-gray-300 focus:border-gray-500 focus:ring-gray-500"
                  required
                />
              </div>

              <div className="text-xs text-gray-300 bg-gray-700/50 p-3 rounded-lg">
                <strong>Note:</strong> Users will be able to view and download files, but cannot upload or manage other users.
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/dashboard')}
                  className="flex-1 bg-gray-700/50 border-gray-600 text-white hover:bg-gray-600/50 hover:text-white transition-all duration-300 hover:scale-[1.02]"
                  disabled={loading}
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="flex-1 bg-gray-500 hover:bg-gray-600 text-white font-semibold transition-all duration-300 hover:scale-[1.02]"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <UserPlus className="mr-2 h-4 w-4" />
                      Create User
                    </>
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};