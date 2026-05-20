
import React from 'react';
import { LayoutDashboard, Terminal, List, PlusCircle, BarChart2 } from 'lucide-react';
import { Vulnerability, ScanLog, NavItem } from './types';

export const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard /> },
  { id: 'new-scan', label: 'New Scan', icon: <PlusCircle /> },
  { id: 'scans', label: 'Scans', icon: <Terminal /> },
  { id: 'results', label: 'Results', icon: <List /> },
  { id: 'benchmark', label: 'Benchmark', icon: <BarChart2 /> },
];

export const MOCK_RESULTS: Vulnerability[] = [
  {
    id: '1',
    url: 'https://api.target-app.com/v1/users',
    parameter: 'id',
    payload: "' OR 1=1 --",
    type: 'SQL Injection',
    severity: 'High',
    responseSnippet: 'HTTP/1.1 200 OK\nContent-Type: application/json\n[{"id":1,"user":"admin","pass":"$2a$12$..."}]',
    fixRecommendation: 'Use parameterized queries or ORMs to handle database inputs. Never concatenate user strings into SQL commands.'
  },
  {
    id: '2',
    url: 'https://target-app.com/search',
    parameter: 'q',
    payload: '<script>alert("XSS")</script>',
    type: 'Cross-Site Scripting (XSS)',
    severity: 'High',
    responseSnippet: '<div>Search results for: <script>alert("XSS")</script></div>',
    fixRecommendation: 'Sanitize all user-controlled input before rendering it in HTML. Use Content Security Policy (CSP) headers.'
  }
];

export const INITIAL_LOGS: ScanLog[] = [
  { id: 'l1', timestamp: '10:45:01', url: '/v1/users', payload: 'test', status: 200, method: 'GET' },
  { id: 'l2', timestamp: '10:45:03', url: '/v1/users?id=1', payload: 'id=1', status: 200, method: 'GET' },
  { id: 'l3', timestamp: '10:45:05', url: '/v1/users?id=1%27', payload: "id=1'", status: 500, method: 'GET' },
];
