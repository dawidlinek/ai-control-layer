import * as React from "react";

type PathIconProps = Omit<React.SVGProps<SVGSVGElement>, "path"> & {
  /** SVG path data in a 24x24 box (several sub-paths separated by spaces / `M`). */
  path: string;
  size?: number;
  strokeWidth?: number;
};

/** Stroke icon from raw path data (the prototype icons). Decorative: `aria-hidden`. */
export function PathIcon({ path, size = 13, strokeWidth = 2, ...rest }: PathIconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      <path d={path} />
    </svg>
  );
}

/** Rogatka "Szlaban" mark: post with a raised striped boom barrier. */
export function RogatkaMark({ size = 16, ...rest }: { size?: number } & React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      <path d="M6.5 21V9.5 M3.5 21h6" strokeWidth="2.2" />
      <path d="M6.5 10L21 4" strokeWidth="2.6" strokeLinecap="butt" strokeDasharray="3.4 2.2" />
      <circle cx="6.5" cy="10" r="2" fill="currentColor" stroke="none" />
    </svg>
  );
}

export const ICON_PATHS = {
  chevronDown: "M6 9l6 6 6-6",
  chevronUp: "M6 15l6-6 6 6",
  close: "M6 6l12 12 M18 6L6 18",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 1 0 0-14z M20 20l-4-4",
  lock: "M7 11V8a5 5 0 0 1 10 0v3 M5 11h14v9H5z",
  copy: "M9 9h11v11H9z M5 15H4V4h11v1",
  calendar: "M4 6h16v14H4z M4 10h16 M8 3v4 M16 3v4",
  bell: "M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z M10 20.5h4",
  keyboard: "M3 7h18v10H3z M7 11h.01 M11 11h.01 M15 11h.01 M8 14h8",
  signOut: "M15 4h4v16h-4 M10 8l-4 4 4 4 M6 12h10",
  conversation: "M4 5h16v11H9l-5 4z M8 9h8 M8 12h5",
  info: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M12 11v5 M12 8v.01",
  check: "M5 12.5l4.5 4.5L19 7.5",
  warning: "M12 3.5l9 16H3z M12 10v4.5 M12 17.5v.01",
  error: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z M6 6l12 12",
  external: "M14 4h6v6 M20 4l-9 9 M18 14v6H4V6h6",
} as const;
