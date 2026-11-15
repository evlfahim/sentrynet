/**
 * SentryNet - LAN Security Scanner
 * Main entry point for the Tauri application.
 */

import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';

// Type definitions for the application
export interface DeviceInfo {
  ip: string;
  mac: string;
  name?: string;
  vendor?: string;
  lastSeen: string;
  firstSeen: string;
}

export interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service?: string;
}

export interface LatencyInfo {
  ip: string;
  icmpMs: number | null;
  httpMs: number | null;
  timestamp: string;
}

export interface ScanResult {
  devices: DeviceInfo[];
  ports: Map<string, PortInfo[]>;
  latencies: LatencyInfo[];
  timestamp: string;
}

// Initialize the application
async function init(): Promise<void> {
  console.log('SentryNet initializing...');
  
  try {
    // Check if Tauri is available
    const version = await invoke('plugin:shell:version');
    console.log('Tauri shell plugin available:', version);
    
    // Get the app window
    const win = getCurrentWindow();
    const title = await win.title();
    console.log('Window title:', title);
    
    // Update UI status
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.textContent = 'Ready. Launch a scan to discover devices.';
    }
    
    console.log('SentryNet initialized successfully');
  } catch (error) {
    console.error('Failed to initialize SentryNet:', error);
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.textContent = 'Error: ' + (error as Error).message;
    }
  }
}

// Run the application
init().catch(console.error);
