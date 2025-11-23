import React from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Clock, AlertTriangle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export const TokenTimer: React.FC = () => {
  const { tokenMinutesRemaining, isAuthenticated } = useAuth();

  if (!isAuthenticated) return null;

  const isExpiringSoon = tokenMinutesRemaining <= 5;
  const isExpiring = tokenMinutesRemaining <= 2;

  return (
    <Badge 
      variant={isExpiring ? "destructive" : isExpiringSoon ? "warning" : "secondary"}
      className="flex items-center gap-1.5 animate-fade-in"
    >
      {isExpiringSoon ? (
        <AlertTriangle className="h-3 w-3" />
      ) : (
        <Clock className="h-3 w-3" />
      )}
      <span className="text-xs font-medium">
        {tokenMinutesRemaining}m remaining
      </span>
    </Badge>
  );
};