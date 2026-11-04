"use client";
import { TiltCard } from "../ui/TiltCard";
import { ShieldCheck, Zap, Globe, ArrowRight } from "lucide-react";
import { motion } from "framer-motion";

export const BentoDashboard = () => {
  return (
    <div className="w-full max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-4 auto-rows-[250px] p-4 relative z-10">
      {/* Card 1: Main Telemetry (Col-span 2) */}
      <TiltCard className="col-span-1 md:col-span-2 glassmorphism flex flex-col p-6 overflow-hidden">
        <div style={{ transform: "translateZ(50px)" }} className="flex justify-between items-start w-full">
          <div>
            <p className="text-neutral-400 text-sm font-medium uppercase tracking-wider mb-2">Real-time System Throughput</p>
            <h3 className="text-5xl font-bold text-white flex items-center gap-4">
              14.2k <span className="text-xl text-neutral-500 font-normal mt-2">req/s</span>
            </h3>
          </div>
          <div className="flex items-center gap-2 bg-green-500/10 text-green-400 px-3 py-1 rounded-full text-xs font-semibold border border-green-500/20">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> Active
          </div>
        </div>
        
        {/* SVG Waveform (Mini sparkline) */}
        <div style={{ transform: "translateZ(30px)" }} className="mt-auto w-full h-24">
          <svg className="w-full h-full" viewBox="0 0 100 30" preserveAspectRatio="none">
            <motion.path
              d="M0,15 Q5,25 15,10 T30,20 T45,5 T60,25 T75,10 T90,20 T100,15"
              fill="none"
              stroke="var(--color-gold)"
              strokeWidth="2"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 2, ease: "easeInOut", repeat: Infinity, repeatType: "reverse" }}
            />
            <motion.path
              d="M0,15 Q5,25 15,10 T30,20 T45,5 T60,25 T75,10 T90,20 T100,15 L100,30 L0,30 Z"
              fill="url(#grad)"
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.5 }}
              transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
            />
            <defs>
              <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-gold)" stopOpacity="0.3" />
                <stop offset="100%" stopColor="transparent" stopOpacity="0" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      </TiltCard>

      {/* Card 2: Security Sandbox (Col-span 1) */}
      <TiltCard className="col-span-1 glassmorphism flex flex-col p-6 justify-between items-center text-center group cursor-pointer">
        <div style={{ transform: "translateZ(40px)" }} className="w-full flex flex-col items-center">
          <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center mb-4 relative">
            <ShieldCheck className="w-8 h-8 text-amber-500" />
            <div className="absolute -top-1 -right-1 w-4 h-4 bg-amber-500 rounded-full border-2 border-dark-surface shadow-[0_0_10px_rgba(245,158,11,0.5)]"></div>
          </div>
          <p className="text-neutral-400 text-sm font-medium uppercase tracking-wider mb-1">Threat & Sandbox Status</p>
          <h3 className="text-2xl font-bold text-white mb-2">0 Detected</h3>
          <p className="text-xs text-neutral-500">Vulnerabilities in last 24h</p>
        </div>
        
        <div style={{ transform: "translateZ(60px)" }} className="w-full mt-4">
          <button className="w-full flex items-center justify-center gap-2 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-sm text-white transition-colors group-hover:border-amber-500/30 group-hover:text-amber-400">
            Inspect Logs <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </TiltCard>

      {/* Card 3: Latency & Compute (Col-span 1) */}
      <TiltCard className="col-span-1 glassmorphism flex flex-col p-6">
        <div style={{ transform: "translateZ(40px)" }} className="flex justify-between items-start mb-6">
          <div className="w-10 h-10 rounded-full bg-neutral-800 flex items-center justify-center">
            <Zap className="w-5 h-5 text-amber-400" />
          </div>
          <span className="text-xs font-mono text-neutral-500 bg-neutral-900 px-2 py-1 rounded">COMPUTE</span>
        </div>
        
        <div style={{ transform: "translateZ(50px)" }} className="mt-auto">
          <p className="text-neutral-400 text-sm font-medium uppercase tracking-wider mb-1">Sub-Millisecond Engine</p>
          <h3 className="text-3xl font-bold text-white mb-4">0.42 <span className="text-sm font-normal text-neutral-500">ms avg</span></h3>
          
          <div className="w-full bg-neutral-800 h-1.5 rounded-full overflow-hidden">
            <motion.div 
              className="h-full bg-amber-500" 
              initial={{ width: "20%" }}
              animate={{ width: "35%" }}
              transition={{ duration: 1.5, repeat: Infinity, repeatType: "reverse", ease: "easeInOut" }}
            />
          </div>
          <p className="text-[10px] text-neutral-500 mt-2 text-right">Memory Footprint</p>
        </div>
      </TiltCard>

      {/* Card 4: Global Node Distribution (Col-span 2) */}
      <TiltCard className="col-span-1 md:col-span-2 glassmorphism flex flex-col p-6 justify-center">
        <div style={{ transform: "translateZ(50px)" }} className="flex items-center gap-4 mb-6">
          <div className="p-3 bg-white/5 rounded-xl border border-white/10">
            <Globe className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white">Edge Cache & Clustering</h3>
            <p className="text-sm text-neutral-400">Global Node Distribution</p>
          </div>
        </div>

        <div style={{ transform: "translateZ(40px)" }} className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          <div>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-neutral-400">Cache Hit Ratio</span>
              <span className="text-white font-mono">99.4%</span>
            </div>
            <div className="w-full bg-neutral-800 h-2 rounded-full overflow-hidden">
              <div className="h-full bg-green-500 w-[99.4%] shadow-[0_0_10px_rgba(34,197,94,0.5)]"></div>
            </div>
          </div>
          
          <div>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-neutral-400">Active Nodes</span>
              <span className="text-white font-mono">48/48</span>
            </div>
            <div className="w-full bg-neutral-800 h-2 rounded-full overflow-hidden">
              <div className="h-full bg-amber-500 w-full shadow-[0_0_10px_rgba(245,158,11,0.5)]"></div>
            </div>
          </div>

          <div>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-neutral-400">Throughput</span>
              <span className="text-white font-mono">1.2 TB/s</span>
            </div>
            <div className="w-full bg-neutral-800 h-2 rounded-full overflow-hidden">
              <motion.div 
                className="h-full bg-blue-500"
                initial={{ width: "70%" }}
                animate={{ width: "85%" }}
                transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
              />
            </div>
          </div>
        </div>
      </TiltCard>
    </div>
  );
};
