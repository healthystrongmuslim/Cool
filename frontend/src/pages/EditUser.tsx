import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiService } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ArrowLeft, Save, Loader2, Edit } from 'lucide-react';
import { toast } from 'sonner';

export const EditUser: React.FC = () => {
  const navigate = useNavigate();
  const { username } = useParams<{ username: string }>();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    new_username: '',
    new_password: '',
    confirm_password: '',
  });

  useEffect(() => {
    if (username) {
      setFormData(prev => ({ ...prev, new_username: username }));
    }
  }, [username]);

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username) {
      toast.error('Invalid user');
      return;
    }

    if (!formData.new_username.trim()) {
      toast.error('Username is required');
      return;
    }

    if (formData.new_password && formData.new_password !== formData.confirm_password) {
      toast.error('Passwords do not match');
      return;
    }

    if (formData.new_password && formData.new_password.length < 3) {
      toast.error('Password must be at least 3 characters long');
      return;
    }

    try {
      setLoading(true);
      
      const updateData: any = {
        current_username: username,
      };

      // Only update username if it changed
      if (formData.new_username !== username) {
        updateData.new_username = formData.new_username;
      }

      // Only update password if provided
      if (formData.new_password) {
        updateData.new_password = formData.new_password;
      }

      // Don't send request if nothing to update
      if (!updateData.new_username && !updateData.new_password) {
        toast.error('No changes to save');
        return;
      }

      await apiService.updateUser(updateData);
      toast.success('User updated successfully');
      navigate('/dashboard');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Update failed');
    } finally {
      setLoading(false);
    }
  };

  if (!username) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <p className="text-destructive">Invalid user specified</p>
          <Button onClick={() => navigate('/dashboard')} className="mt-4">
            Go Back
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/10 p-4">
      <div className="container mx-auto max-w-md">
        {/* Back Button */}
        <div className="mb-6">
          <Button 
            onClick={() => navigate('/dashboard')} 
            variant="ghost" 
            size="sm"
            className="mb-4"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
        </div>

        <Card className="animate-fade-in backdrop-blur-sm bg-card/50 border-border/50 shadow-elegant">
          <CardHeader className="text-center">
            <div className="mx-auto w-12 h-12 bg-gradient-accent rounded-full flex items-center justify-center mb-4">
              <Edit className="h-6 w-6 text-accent-foreground" />
            </div>
            <CardTitle>Edit User</CardTitle>
            <CardDescription>
              Update user information for: <strong>{username}</strong>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="new_username">Username</Label>
                <Input
                  id="new_username"
                  type="text"
                  placeholder="Enter new username"
                  value={formData.new_username}
                  onChange={(e) => handleInputChange('new_username', e.target.value)}
                  disabled={loading}
                  className="bg-background/50"
                  required
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="new_password">New Password (optional)</Label>
                <Input
                  id="new_password"
                  type="password"
                  placeholder="Enter new password (leave blank to keep current)"
                  value={formData.new_password}
                  onChange={(e) => handleInputChange('new_password', e.target.value)}
                  disabled={loading}
                  className="bg-background/50"
                />
              </div>

              {formData.new_password && (
                <div className="space-y-2">
                  <Label htmlFor="confirm_password">Confirm New Password</Label>
                  <Input
                    id="confirm_password"
                    type="password"
                    placeholder="Confirm new password"
                    value={formData.confirm_password}
                    onChange={(e) => handleInputChange('confirm_password', e.target.value)}
                    disabled={loading}
                    className="bg-background/50"
                    required={!!formData.new_password}
                  />
                </div>
              )}

              <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-lg">
                <strong>Note:</strong> Leave password fields blank if you don't want to change the password.
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/dashboard')}
                  className="flex-1"
                  disabled={loading}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="flex-1"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="mr-2 h-4 w-4" />
                      Save Changes
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