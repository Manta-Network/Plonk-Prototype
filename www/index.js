import { NativeContext, bench_native_poseidon, PlonkContext, bench_plonk_poseidon, R1CSContext, bench_r1cs_poseidon } from "wasm-prover";

const pre = document.getElementById("wasm-prover");

// compute the median of an array
const median = arr => {
  const mid = Math.floor(arr.length / 2),
  nums = [...arr].sort((a, b) => a - b);
  return arr.length % 2 !== 0 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
};

function wasm_bench_native_poseidon() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const input = new NativeContext();
        const t0 = performance.now();
        bench_native_poseidon(input);
        const t1 = performance.now();
        return t1 - t0;
      }
  );

  let out_text = `bench_native_poseidon(), median performance: ${median(perf)} ms \n`;
  return out_text;
}

function wasm_bench_plonk_poseidon() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const input = new PlonkContext();
        const t0 = performance.now();
        bench_plonk_poseidon(input);
        const t1 = performance.now();
        return t1 - t0;
      }
  );

  let out_text = `bench_plonk_poseidon(), median performance: ${median(perf)} ms \n`;
  return out_text;
}

function wasm_bench_r1cs_poseidon() {
  const repeat = 5;
  const perf = Array.from(
      {length: repeat},
      (_, i) => {
        const input = new R1CSContext();
        const t0 = performance.now();
        bench_r1cs_poseidon(input);
        const t1 = performance.now();
        return t1 - t0;
      }
  );

  let out_text = `bench_r1cs_poseidon(), median performance: ${median(perf)} ms \n`;
  return out_text;
}

// benchmarking native poseidon
pre.textContent = wasm_bench_native_poseidon();

// benchmarking plonk poseidon
pre.textContent = wasm_bench_plonk_poseidon();

// benchmarking r1cs poseidon
pre.textContent = wasm_bench_r1cs_poseidon();