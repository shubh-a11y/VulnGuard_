"use client";
import { motion } from "framer-motion";
import { cn } from "../../lib/utils";

export const BackgroundBeams = ({ className }: { className?: string }) => {
  return (
    <div
      className={cn(
        "absolute inset-0 z-0 flex items-center justify-center overflow-hidden",
        className
      )}
    >
      <div className="absolute inset-0 bg-dark-bg">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]"></div>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1.5 }}
          className="absolute inset-0 flex items-center justify-center"
        >
          <svg
            width="100%"
            height="100%"
            viewBox="0 0 1440 800"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            className="absolute inset-0 w-full h-full"
          >
            {/* Animated beams */}
            <motion.path
              d="M-200 400C100 200 500 600 1600 200"
              stroke="var(--color-gold)"
              strokeWidth="1.5"
              strokeOpacity="0.2"
              fill="none"
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 0.2 }}
              transition={{ duration: 3, ease: "easeInOut", repeat: Infinity, repeatType: "reverse" }}
            />
            <motion.path
              d="M-200 600C200 800 600 200 1600 500"
              stroke="var(--color-gold)"
              strokeWidth="2"
              strokeOpacity="0.15"
              fill="none"
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 0.15 }}
              transition={{ duration: 4, ease: "easeInOut", repeat: Infinity, repeatType: "reverse", delay: 1 }}
            />
            <motion.path
              d="M-200 200C300 -100 800 500 1600 100"
              stroke="var(--color-gold)"
              strokeWidth="1"
              strokeOpacity="0.2"
              fill="none"
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 0.2 }}
              transition={{ duration: 3.5, ease: "easeInOut", repeat: Infinity, repeatType: "reverse", delay: 0.5 }}
            />
          </svg>
        </motion.div>
      </div>
    </div>
  );
};
