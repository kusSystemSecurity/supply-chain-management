/**
 * Utility functions for the frontend
 */

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { Severity } from "./types";

/**
 * Merge Tailwind CSS classes
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a date string to a human-readable format
 */
export function formatDate(date: string | Date): string {
  const d = typeof date === "string" ? new Date(date) : date;

  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Get Tailwind CSS classes for severity badge background color
 */
export function getSeverityBadgeColor(severity: string): string {
  const sev = severity.toUpperCase();

  switch (sev) {
    case "CRITICAL":
      return "bg-purple-500";
    case "HIGH":
      return "bg-red-500";
    case "MEDIUM":
      return "bg-orange-500";
    case "LOW":
      return "bg-yellow-500";
    default:
      return "bg-gray-500";
  }
}

/**
 * Get Tailwind CSS classes for severity text color
 */
export function getSeverityColor(severity: string): string {
  const sev = severity.toUpperCase();

  switch (sev) {
    case "CRITICAL":
      return "text-purple-600 dark:text-purple-400";
    case "HIGH":
      return "text-red-600 dark:text-red-400";
    case "MEDIUM":
      return "text-orange-600 dark:text-orange-400";
    case "LOW":
      return "text-yellow-600 dark:text-yellow-400";
    default:
      return "text-gray-600 dark:text-gray-400";
  }
}

/**
 * Format a number to a fixed number of decimal places
 */
export function formatNumber(num: number | null | undefined, decimals: number = 2): string {
  if (num === null || num === undefined) return "N/A";
  return num.toFixed(decimals);
}
