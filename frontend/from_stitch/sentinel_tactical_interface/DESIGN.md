---
name: Sentinel Tactical Interface
colors:
  surface: '#031427'
  surface-dim: '#031427'
  surface-bright: '#2a3a4f'
  surface-container-lowest: '#000f21'
  surface-container-low: '#0b1c30'
  surface-container: '#102034'
  surface-container-high: '#1b2b3f'
  surface-container-highest: '#26364a'
  on-surface: '#d3e4fe'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#d3e4fe'
  inverse-on-surface: '#213145'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#adc6ff'
  on-secondary: '#002e6a'
  secondary-container: '#0566d9'
  on-secondary-container: '#e6ecff'
  tertiary: '#d0bcff'
  on-tertiary: '#3c0091'
  tertiary-container: '#b090ff'
  on-tertiary-container: '#4600a7'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#adc6ff'
  on-secondary-fixed: '#001a42'
  on-secondary-fixed-variant: '#004395'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d0bcff'
  on-tertiary-fixed: '#23005c'
  on-tertiary-fixed-variant: '#5516be'
  background: '#031427'
  on-background: '#d3e4fe'
  surface-variant: '#26364a'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-margin: 24px
  gutter: 16px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
  max-width: 1440px
---

## Brand & Style

The design system is engineered for high-stakes security environments where clarity, speed, and precision are paramount. The brand personality is authoritative and vigilant, yet sophisticated—evoking the feeling of a high-tech command center. It targets cybersecurity professionals, DevOps engineers, and system architects who require an interface that minimizes cognitive load during critical audits.

The aesthetic leans heavily into **Glassmorphism** and **Modern Enterprise** styles. It utilizes deep, layered transparencies, subtle backdrop blurs, and high-precision glowing accents to denote active states and system health. The interface feels "alive" through the use of light-emitting borders and functional gradients that guide the eye toward critical security vulnerabilities.

## Colors

This design system uses a sophisticated dark-palette hierarchy designed to reduce eye strain during long auditing sessions.

- **Primary Emerald (#10B981):** Used for "Secure" states, primary actions, and brand reinforcement. It represents the "Go" signal in a security context.
- **Accent Electric Blue (#3B82F6):** Reserved for interactive elements, links, and selection states. It distinguishes user-initiated actions from system-status indicators.
- **Semantic Palette:** Danger Red (#EF4444) for critical breaches, Warning Amber (#F59E0B) for vulnerabilities, and Success Green (#22C55E) for completed scans.
- **Surface Strategy:** Backgrounds utilize a linear gradient from Deep Slate (#0F172A) to Dark Blue (#1E293B). Surfaces are rendered with 60-80% opacity and a `20px` backdrop blur to create a sense of physical depth.

## Typography

Typography is bifurcated into two functional roles: **Inter** handles all UI navigation, messaging, and structural headers, while **JetBrains Mono** is utilized exclusively for technical data, terminal logs, and system paths.

For maximum readability against dark backgrounds, body text should use a slightly off-white (Slate 200) to avoid "vibrating" text. All technical labels use uppercase styling with increased letter spacing to differentiate metadata from content. Code blocks should maintain a high contrast ratio to ensure accessibility when reviewing complex security logs.

## Layout & Spacing

The system employs a **12-column fluid grid** for dashboard views and a **fixed-width centered layout** for documentation and reporting. 

- **Grid:** 16px gutters provide sufficient breathing room for dense data tables.
- **Breakpoints:** Mobile (<768px) collapses to a 1-column stack; Tablet (768px-1024px) uses an 8-column grid; Desktop (>1024px) utilizes the full 12-column array.
- **Spacing Logic:** All spacing is based on a 4px base unit to ensure alignment of technical fonts like JetBrains Mono, which rely on rigid vertical rhythms.

## Elevation & Depth

Depth is established through **translucency tiers** rather than traditional drop shadows.

1.  **Level 0 (Base):** The core gradient background.
2.  **Level 1 (Cards/Panels):** Surface-Dark-Blue at 60% opacity with a `1px` border (White @ 10% opacity) and `blur(12px)`.
3.  **Level 2 (Modals/Popovers):** Surface-Dark-Blue at 80% opacity with a `1px` border (White @ 20% opacity) and an inner glow of the Primary Emerald or Accent Blue to denote focus.
4.  **Level 3 (Interaction):** Hover states utilize a `0 0 15px` outer glow in the element's functional color (e.g., a Red glow for a critical delete action).

## Shapes

The shape language is **Soft (0.25rem base)**, reflecting the precision of a technical tool while maintaining a modern, premium feel. 

- **Small Components:** Checkboxes and small buttons use a 4px (0.25rem) radius.
- **Medium Components:** Large buttons and input fields use a 8px (0.5rem) radius.
- **Large Components:** Main dashboard cards and modal containers use a 12px (0.75rem) radius. 
This tiered approach ensures that larger containers don't appear overly "round" or playful, maintaining the professional integrity of an enterprise security tool.

## Components

- **Buttons:** Primary buttons are solid Primary Emerald with white text. Secondary buttons use a "ghost" style with a 1px border and a subtle backdrop blur.
- **High-Contrast Badges:** Severity levels (Critical, High, Medium, Low) use saturated background colors with white text and a soft outer glow in the respective status color.
- **Vertical Steppers:** Used for multi-stage audits. Completed steps are Primary Emerald; active steps have an Electric Blue pulse animation.
- **Detailed Cards:** Feature a top-accent border (2px) color-coded to the content's severity. They should include a subtle `0.5` opacity background pattern (hex-grid or dots) to reinforce the "tech" aesthetic.
- **Input Fields:** Utilize a dark, recessed background with a 1px border that glows Electric Blue upon focus. Placeholder text should be in Slate 500.
- **Code Blocks:** Wrapped in a Level 2 container with syntax highlighting that matches the primary and secondary system colors.