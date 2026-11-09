// Icon.jsx — Guardian.AI inline icon set.
//
// One consistent set: 24px grid, stroke 1.5, round caps, currentColor.
// No emoji anywhere in the product — every glyph is drawn here.

const PATHS = {
  "shield-filled": { type: "filled", d: "M12 2.5l8 3.4v6.5c0 5-3.5 8.5-8 10.1-4.5-1.6-8-5.1-8-10.1V5.9l8-3.4z" },
  shield: ["M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z"],
  "shield-check": [
    "M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z",
    "M9 11.8l2 2 4-4",
  ],
  "shield-alert": [
    "M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z",
    "M12 8.5v4",
    "M12 15.6h.01",
  ],
  mail: ["M4 6h16v12H4z", "M4 7.2l8 5.8 8-5.8"],
  link: [
    "M10.5 13.5a4.5 4.5 0 0 0 6.4 0l2-2a4.5 4.5 0 0 0-6.4-6.4l-1 1",
    "M13.5 10.5a4.5 4.5 0 0 0-6.4 0l-2 2a4.5 4.5 0 0 0 6.4 6.4l1-1",
  ],
  paperclip: [
    "M19.5 11.5l-8 8a4.5 4.5 0 0 1-6.4-6.4l8.5-8.5a3 3 0 0 1 4.3 4.3l-8.5 8.5a1.5 1.5 0 0 1-2.2-2.2l7.7-7.7",
  ],
  search: ["M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z", "M16.2 16.2L21 21"],
  alert: ["M12 4l9 16H3l9-16z", "M12 10v4", "M12 17h.01"],
  info: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M12 11v5", "M12 7.8h.01"],
  check: ["M5 12.5l4.5 4.5L19 7"],
  "check-circle": ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M8.4 12.4l2.6 2.6 4.6-5"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  copy: [
    "M9 9h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z",
    "M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1",
  ],
  "arrow-left": ["M19 12H5", "M11 18l-6-6 6-6"],
  "arrow-right": ["M5 12h14", "M13 6l6 6-6 6"],
  target: [
    "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
    "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
    "M12 11.5h.01",
  ],
  layers: ["M12 3l9 5-9 5-9-5 9-5z", "M3 12.5l9 5 9-5", "M3 16.5l9 5 9-5"],
  activity: ["M3 12h4l2.5 7L14 5l2.5 7H21"],
  lock: ["M5 10h14v11H5z", "M8.5 10V7a3.5 3.5 0 0 1 7 0v3"],
  globe: [
    "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
    "M3.5 12h17",
    "M12 3c2.6 3.2 2.6 14.8 0 18M12 3c-2.6 3.2-2.6 14.8 0 18",
  ],
  blocks: [
    "M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z",
    "M12 12l8-4.5",
    "M12 12v9",
    "M12 12L4 7.5",
  ],
  sun: [
    "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
    "M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19",
  ],
  moon: ["M20.5 14.6A8.6 8.6 0 0 1 9.4 3.5a8.6 8.6 0 1 0 11.1 11.1z"],
  contrast: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M12 3v18"],
  file: ["M6 3h7l5 5v13H6z", "M13 3v5h5"],
  message: ["M21 11.6a8.4 8.4 0 0 1-12.4 7.4L4 20.5l1.5-4.4A8.4 8.4 0 1 1 21 11.6z"],
  zap: ["M13 3l-8 11h6l-1 7 8-11h-6l1-7z"],
  upload: ["M12 16V5", "M7.5 9.5L12 5l4.5 4.5", "M4 19h16"],
  scan: ["M4 8V5h4", "M20 8V5h-4", "M4 16v3h4", "M20 16v3h-4", "M7 12h10"],
  external: ["M14 4h6v6", "M20 4l-9 9", "M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"],
  refresh: ["M20 11a8 8 0 1 0-2.3 6.3", "M20 5v6h-6"],
};

function Icon({ name, size = 16, strokeWidth = 1.5, className = "", title }) {
  const entry = PATHS[name] || PATHS.info;
  const filled = !Array.isArray(entry) && entry?.type === "filled";
  const paths = filled ? [entry.d] : entry;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={filled ? "currentColor" : "none"}
      stroke={filled ? "none" : "currentColor"}
      strokeWidth={filled ? undefined : strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden={title ? undefined : "true"}
      role={title ? "img" : undefined}
      focusable="false"
    >
      {title && <title>{title}</title>}
      {paths.map((d, i) => (
        <path key={i} d={d} />
      ))}
    </svg>
  );
}

export default Icon;
