# Portable analog corpus

These decks are original, clean-room examples written for this repository.
They imitate common educational and review-oriented SPICE organization without
copying a PDK, vendor model, textbook listing, or third-party netlist. The files
are distributed under the repository MIT license.

- `two_stage_ota.sp` exercises hierarchical bias, gain, and output stages.
- `rc_sensor_frontend.sp` exercises continuation lines, parameters, and a
  reusable passive subcircuit.
- `primitives.lib` contains deliberately non-physical placeholder `.model`
  declarations. It is parser input only and is not suitable for simulation.
