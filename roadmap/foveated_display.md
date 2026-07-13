You are the lead graphics architect for AnonymOS. Your task is to redesign the desktop compositor and rendering pipeline to support an entirely new optional display mode called **Spatial Rendering Mode**. This is a compositor-level feature—not an application feature. Existing applications must continue to work without modification.

The goal is to make a standard monitor behave like a real window into a virtual world while simultaneously improving performance through eye-tracked foveated rendering.

=========================
PRIMARY OBJECTIVES
=========================

Implement the following as native compositor features:

• Eye-tracked foveated rendering
• Head tracking
• Eye tracking
• Perspective-correct desktop rendering
• Perspective-aware wallpapers
• Depth-aware rendering
• GPU accelerated rendering
• Variable Rate Shading (VRS)
• Adaptive resolution rendering
• Low latency prediction
• Optional spatial UI effects

This mode should be optional and configurable per user session.

=========================
HEAD TRACKING
=========================

Implement a hardware abstraction layer supporting multiple tracking backends including:

- OpenXR
- Tobii
- OpenTrack
- Webcam (OpenCV / MediaPipe)
- Meta Smart Glasses
- Future tracking devices

The compositor should continuously estimate:

- Head position (X,Y,Z)
- Head rotation (pitch, yaw, roll)
- Tracking confidence
- Timestamp

Target refresh rate:

120–240 Hz whenever hardware permits.

The compositor should expose a unified HeadTracker interface so new hardware can be added without changing compositor logic.

=========================
EYE TRACKING
=========================

Create an EyeTracker abstraction capable of supporting:

- Tobii
- OpenXR eye tracking
- Meta Smart Glasses
- Webcam gaze estimation
- Future hardware

The interface should provide:

- gaze position
- normalized screen coordinates
- confidence
- calibration state
- timestamp

Support 120–240 Hz updates.

Implement calibration tools.

=========================
SPATIAL CAMERA
=========================

Replace the assumption that the desktop is a flat image.

Instead:

The desktop exists inside a virtual scene viewed through a virtual camera.

The camera moves based on the user's head position.

Examples:

Move head left:

Desktop perspective shifts realistically.

Move right:

Perspective changes.

Move closer:

Desktop appears larger.

Move farther:

Desktop appears farther away.

The effect should feel identical to looking through a physical window.

The desktop should never appear to stretch.

Perspective should be physically correct.

=========================
PERSPECTIVE WALLPAPERS
=========================

Replace static wallpapers with perspective-aware environments.

Supported wallpaper types:

• Standard image
• Image + depth map
• Layered images
• glTF scene
• USD scene
• FBX scene
• Procedural environment

If only a 2D wallpaper exists:

Automatically generate a depth map using a local monocular depth estimation model (e.g., MiDaS, Depth Anything, or equivalent) and cache the result.

The wallpaper renderer should convert the depth map into displaced geometry so that hidden portions of the scene become visible as the user's head moves.

The wallpaper should appear to extend behind the monitor rather than remaining a flat image.

This should create convincing parallax.

=========================
SPATIAL DESKTOP
=========================

Desktop icons, windows, docks, and panels should remain anchored to the display plane while the wallpaper exists behind them.

The wallpaper should respond to head movement.

UI elements should remain readable.

Optionally allow:

• Slight depth offset
• 3D hover animations
• Billboard icons
• Layered desktop effects

=========================
FOVEATED RENDERING
=========================

Implement compositor-level gaze-directed rendering.

Rendering quality should follow the user's gaze.

Example:

Central vision:

100%

Near peripheral:

70%

Outer peripheral:

40%

Far peripheral:

20%

Use smooth Gaussian falloff rather than circular hard edges.

Applications should require zero modification.

=========================
VARIABLE RATE SHADING
=========================

Use GPU Variable Rate Shading when available.

Support:

• Vulkan
• DirectX
• Metal

Fallback:

Multiple render targets.

Automatically choose the highest performance implementation available.

=========================
PREDICTIVE RENDERING
=========================

Implement gaze prediction using Kalman filtering or equivalent prediction algorithms.

Predict approximately 10–20 milliseconds ahead to reduce perceived latency.

Likewise predict head motion for smoother perspective updates.

=========================
WINDOW RENDERING
=========================

Assign every window a rendering priority determined by:

- Focus
- Gaze distance
- Animation state
- Interaction

Focused windows receive maximum quality.

Background windows may reduce:

- AA quality
- shadow resolution
- blur quality
- sampling
- refresh frequency

without visual degradation.

=========================
ADAPTIVE REFRESH
=========================

Support asynchronous compositor updates.

Example:

Focused region:

240 Hz

Peripheral region:

90 Hz

Wallpaper:

30–60 Hz

Only redraw what actually changes.

=========================
GPU PIPELINE
=========================

Redesign the rendering pipeline to include:

Input

↓

Head Tracking

↓

Eye Tracking

↓

Prediction

↓

Spatial Camera

↓

Perspective Transform

↓

Wallpaper Renderer

↓

Window Renderer

↓

Foveated Renderer

↓

Variable Rate Shading

↓

Final Compositor

↓

Display

This pipeline should be modular.

=========================
MULTI-LAYER COMPOSITOR
=========================

Render the desktop using separate layers:

Foreground effects

↓

Windows

↓

Panels

↓

Desktop icons

↓

Wallpaper geometry

↓

Background lighting

Each layer should be independently composited.

=========================
GRAPHICS FEATURES
=========================

Support:

• HDR
• VRR
• 4K
• 8K
• Multi-monitor
• Vulkan renderer
• OpenGL fallback
• Software renderer fallback

=========================
CONFIGURATION
=========================

Add a settings panel containing:

Spatial Rendering Mode

Enabled

Disabled

Auto

Head Tracking

Eye Tracking

Perspective Wallpaper

Wallpaper Depth Strength

Foveated Rendering

Foveation Strength

Prediction

Variable Rate Shading

Performance Mode

Battery Saver

Latency Optimization

Debug Visualization

=========================
PRIVACY
=========================

Tracking data must never leave the local machine.

No cloud processing.

Camera frames should be discarded immediately after pose estimation unless debugging is explicitly enabled.

=========================
ARCHITECTURE
=========================

Design the implementation to be modular with clear interfaces so future features can be added without redesigning the compositor.

Future expansion should support:

• Autostereoscopic displays
• Light-field displays
• Transparent AR displays
• Neural rendering
• AI-generated depth-aware wallpapers
• Volumetric desktop widgets
• Multi-user tracked displays
• OpenXR integration

=========================
IMPLEMENTATION REQUIREMENTS
=========================

This feature must integrate cleanly into the existing AnonymOS compositor.

Maintain complete backward compatibility.

Applications must not require modification.

The compositor should automatically detect supported hardware and gracefully fall back to normal desktop rendering if tracking hardware is unavailable.

The implementation should prioritize low latency, modularity, maintainability, and high performance. Produce production-quality architecture, interfaces, rendering pipeline, configuration system, compositor changes, GPU integration, and documentation suitable for a modern next-generation desktop operating system.