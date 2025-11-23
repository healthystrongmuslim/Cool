import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Shield, User, Loader2, UserCheck } from 'lucide-react';
import { toast } from 'sonner';

export const Login: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [credentials, setCredentials] = useState({
    username: '',
    password: '',
  });

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (isAdmin: boolean) => {
    if (!credentials.username || !credentials.password) {
      toast.error('Please fill in all fields');
      return;
    }

    setIsLoading(true);
    try {
      const success = await login(credentials.username, credentials.password, isAdmin);
      if (!success) {
        toast.error('Invalid credentials');
        setCredentials(prev => ({ ...prev, password: '' })); // Clear password on fail
      }
    } catch (error) {
      toast.error('Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (field: string, value: string) => {
    setCredentials((prev) => ({ ...prev, [field]: value }));
  };

  return (
    <div className="min-h-screen flex">
      {/* Left 2/3 with background image */}
      <div
        className="w-2/3 hidden md:block bg-cover bg-center"
        style={{
          backgroundImage: `linear-gradient(to bottom, rgba(15, 23, 42, 0.3), rgba(15, 23, 42, 0.5)), url(/logo.png)`,
        }}
      ></div>

      {/* Right 1/3 login section */}
      <div className="w-full md:w-1/3 flex flex-col justify-center items-center bg-gray-900 text-white p-6 -mt-8 relative">
        <div className="w-full max-w-sm animate-fade-in">
          {/* Heading */}
          <div className="text-center mb-4 relative">
            <h1 className="text-2xl font-bold hover:scale-105 transition-transform duration-300 ease-in-out">
               Cloud Based<br />
              SECURE SERVER
            </h1>
          </div>

          {/* Login Card */}
          <Card className="backdrop-blur-sm bg-gray-800/40 border border-gray-700 shadow-md rounded-lg transition-all duration-200 px-3 py-1 text-sm">
            <CardHeader className="text-center space-y-1">
              <CardTitle className="text-white text-lg">Welcome Back</CardTitle>
              <CardDescription className="text-gray-300 text-sm">
                Choose your login type to continue
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-2">
              <Tabs defaultValue="user" className="w-full text-sm">
                <TabsList className="grid w-full grid-cols-2 mb-4 bg-gray-700/40 rounded-md h-9">
                  <TabsTrigger
                    value="user"
                    className="flex items-center justify-center gap-1 text-gray-300 hover:text-white data-[state=active]:bg-gray-500 data-[state=active]:text-white text-xs transition-all duration-200"
                  >
                    <User className="h-3 w-3" />
                    User
                  </TabsTrigger>
                  <TabsTrigger
                    value="admin"
                    className="flex items-center justify-center gap-1 text-gray-300 hover:text-white data-[state=active]:bg-gray-500 data-[state=active]:text-white text-xs transition-all duration-200"
                  >
                    <Shield className="h-3 w-3" />
                    Admin
                  </TabsTrigger>
                </TabsList>

                {/* Username */}
                <div className="space-y-3">
                  <div className="space-y-1">
                    <Label htmlFor="username" className="text-gray-300 text-sm">Username</Label>
                    <Input
                      id="username"
                      type="text"
                      placeholder="Username"
                      value={credentials.username}
                      onChange={(e) => handleInputChange('username', e.target.value)}
                      disabled={isLoading}
                      className="h-8 bg-gray-700 border-gray-600 text-white placeholder-gray-400 text-sm"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="password" className="text-gray-300 text-sm">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      placeholder="Password"
                      value={credentials.password}
                      onChange={(e) => handleInputChange('password', e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !isLoading) {
                          handleSubmit(false);
                        }
                      }}
                      disabled={isLoading}
                      className="h-8 bg-gray-700 border-gray-600 text-white placeholder-gray-400 text-sm"
                    />
                  </div>
                </div>

                {/* User Login Button */}
                <TabsContent value="user" className="mt-4">
                  <div className="space-y-3">
                    <div className="text-xs text-gray-300 bg-gray-700/50 p-2 rounded-md">
                      <strong>User Access:</strong> Enter user credentials to login as regular user
                    </div>
                  <Button
                    onClick={() => handleSubmit(false)}
                    disabled={isLoading}
                    className="w-full h-9 bg-gray-500 hover:bg-gray-600 text-white font-medium text-sm"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="mr-2 h-3 w-3 animate-spin" />
                        Signing in...
                      </>
                    ) : (
                      <>
                        <UserCheck className="mr-2 h-3 w-3" />
                        Sign in as User
                      </>
                    )}
                  </Button>
                  </div>
                </TabsContent>

                {/* Admin Login Button */}
                <TabsContent value="admin" className="mt-4">
                  <div className="space-y-3">
                    <div className="text-xs text-gray-300 bg-gray-700/50 p-2 rounded-md">
                      <strong>Admin Access:</strong> Use admin credentials for system management
                    </div>
                    <Button
                      onClick={() => handleSubmit(true)}
                      disabled={isLoading}
                      className="w-full h-9 bg-gray-500 hover:bg-gray-600 text-white font-medium text-sm"
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="mr-2 h-3 w-3 animate-spin" />
                          Authenticating...
                        </>
                      ) : (
                        <>
                          <Shield className="mr-2 h-3 w-3" />
                          Admin Login
                        </>
                      )}
                    </Button>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

       

      </div>
    </div>
  );
};
