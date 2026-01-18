import { Shield, AlertTriangle, Brain } from 'lucide-react';

export function Hero() {
  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 bg-[#E09B3D]/10 border border-[#E09B3D]/30 rounded-full px-4 py-2 mb-6">
            <Shield className="w-4 h-4 text-[#E09B3D]" />
            <span className="text-sm text-[#E09B3D] font-medium">AI-Powered API Security</span>
          </div>
          
          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold mb-6 leading-tight text-[#023D50]">
            Stop API Key Theft <br />
            <span className="gradient-text">Before It Costs You</span>
          </h1>
          
          <p className="text-xl text-[#456A77] mb-12 max-w-3xl mx-auto">
            HoneyKey deploys intelligent honeypot API keys that detect and track unauthorized access attempts in real-time, 
            generating actionable security reports powered by AI.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-16">
            <div className="incident-card rounded-xl p-6">
              <div className="w-12 h-12 bg-[#DC5037]/20 rounded-lg flex items-center justify-center mb-4">
                <AlertTriangle className="w-6 h-6 text-[#DC5037]" />
              </div>
              <h3 className="text-lg font-semibold mb-2 text-[#023D50]">The Problem</h3>
              <p className="text-[#456A77]">
                Leaked API keys cost companies millions annually through data breaches, 
                unauthorized access, and service abuse.
              </p>
            </div>
            
            <div className="incident-card rounded-xl p-6">
              <div className="w-12 h-12 bg-[#E09B3D]/20 rounded-lg flex items-center justify-center mb-4">
                <Shield className="w-6 h-6 text-[#E09B3D]" />
              </div>
              <h3 className="text-lg font-semibold mb-2 text-[#023D50]">The Solution</h3>
              <p className="text-[#456A77]">
                Deploy realistic honeypot API keys that blend seamlessly with your infrastructure 
                to catch attackers in the act.
              </p>
            </div>
            
            <div className="incident-card rounded-xl p-6">
              <div className="w-12 h-12 bg-[#16A085]/20 rounded-lg flex items-center justify-center mb-4">
                <Brain className="w-6 h-6 text-[#16A085]" />
              </div>
              <h3 className="text-lg font-semibold mb-2 text-[#023D50]">AI Analysis</h3>
              <p className="text-[#456A77]">
                Automatically generate comprehensive security reports with detailed threat analysis and actionable insights.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}