#!/bin/bash
set -e

DMD=/home/bruns/Documents/anonymos-dmd/dmd
RT_DIR=/home/bruns/Documents/anonymos-dmd/druntime
PHOBOS_DIR=/home/bruns/Documents/anonymos-phobos
SRC_DIR=/home/bruns/Documents/-sh/src
LOGFILE=build.log
BUILD_DIR=build
OUTPUT="$BUILD_DIR/interpreter"
MSTD_DIR=/home/bruns/Documents/-sh

mkdir -p "$BUILD_DIR"
echo "Starting full build at $(date)" > "$LOGFILE"

###########################################
# Step 1: Build druntime
###########################################
echo -e "\n=== Building druntime ===" >> "$LOGFILE"
DRUNTIME_OBJS=()
for f in $(find "$RT_DIR/src" -name "*.d"); do
    OBJ="$BUILD_DIR/$(basename "$f" .d).o"
    DRUNTIME_OBJS+=("$OBJ")
    echo "Compiling $f -> $OBJ" >> "$LOGFILE"
    $DMD -c -I"$RT_DIR/src" -of="$OBJ" "$f" >>"$LOGFILE" 2>&1
done

###########################################
# Step 2: Build Phobos
###########################################
echo -e "\n=== Building Phobos subset ===" >> "$LOGFILE"
PHOBOS_OBJS=()
for f in $(find "$PHOBOS_DIR/std" -name "*.d"); do
    OBJ="$BUILD_DIR/$(basename "$f" .d).o"
    PHOBOS_OBJS+=("$OBJ")
    echo "Compiling $f -> $OBJ" >> "$LOGFILE"
    $DMD -c -I"$RT_DIR/src" -I"$PHOBOS_DIR" -of="$OBJ" "$f" >>"$LOGFILE" 2>&1
done

###########################################
# Step 2.5: Build mstd modules
###########################################
echo -e "\n=== Building mstd modules ===" >> "$LOGFILE"
MSTD_OBJS=()
for f in $(find "$MSTD_DIR/mstd" -name "*.d"); do
    base=$(basename "$f" .d)
    OBJ="$BUILD_DIR/mstd_$base.o"
    MSTD_OBJS+=("$OBJ")
    echo "Compiling $f -> $OBJ" >> "$LOGFILE"
    $DMD -c -I"$RT_DIR/src" -I"$PHOBOS_DIR" -I"$SRC_DIR" -I"$MSTD_DIR" -of="$OBJ" "$f" >>"$LOGFILE" 2>&1
done


###########################################
# Step 3: Compile User Modules
###########################################
echo -e "\n=== Building interpreter and modules ===" >> "$LOGFILE"
USER_OBJS=()

# Find unsupported files for info (not excluded here unless example.d)
unsupported=$(grep -lE '\b(Exception|import std|try|catch|throw)\b' "$SRC_DIR"/*.d || true)

for f in "$SRC_DIR"/*.d; do
    base=$(basename "$f")
    # Skip demonstration or broken modules
    if [[ "$base" == "example.d" ]]; then
        continue
    fi
    OBJ="$BUILD_DIR/${base%.d}.o"
    USER_OBJS+=("$OBJ")

    if [[ " $unsupported " == *" $f "* ]]; then
        echo "⚠️  $f uses exceptions or std, compiling anyway" >> "$LOGFILE"
    fi

    echo "Compiling $f -> $OBJ" >> "$LOGFILE"
    $DMD -c -I"$RT_DIR/src" -I"$PHOBOS_DIR" -I"$SRC_DIR" -I"$MSTD_DIR" -of="$OBJ" "$f" >>"$LOGFILE" 2>&1
done

###########################################
# Step 4: Link All Together
###########################################
echo -e "\n=== Linking interpreter ===" >> "$LOGFILE"
$DMD -I"$RT_DIR/src" -I"$PHOBOS_DIR" -I"$SRC_DIR" -I"$MSTD_DIR" \
     -of="$OUTPUT" \
     "${USER_OBJS[@]}" \
     "${DRUNTIME_OBJS[@]}" \
     "${PHOBOS_OBJS[@]}" \
     "${MSTD_OBJS[@]}" \
     >>"$LOGFILE" 2>&1


echo -e "\n✅ Build finished at $(date)" >> "$LOGFILE"
echo "Output: $OUTPUT"
