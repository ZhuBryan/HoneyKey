import { Key, Eye, FileText, Bell } from 'lucide-react';

export function HowItWorks() {
  const steps = [
    {
      icon: Key,
      title: 'Deploy Honeypots',
      description: 'Create realistic-looking API keys and strategically place them in your repositories, documentation, or test environments.',
    },
    {
      icon: Eye,
      title: 'Monitor Usage',
      description: 'Our system tracks all usage attempts of honeypot keys, capturing IP addresses, request patterns, and behavioral data.',
    },
    {
      icon: Bell,
      title: 'Detect Threats',
      description: 'Advanced AI analyzes usage patterns to distinguish between legitimate testing and malicious exploitation attempts.',
    },
    {
      icon: FileText,
      title: 'Generate Reports',
      description: 'Automatically create detailed security reports with actionable insights and threat analysis.',
    },
  ];

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8 bg-[#FFF8F0]">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold mb-4 text-[#023D50]">
            How <span className="gradient-text">HoneyKey</span> Works
          </h2>
          <p className="text-xl text-[#456A77] max-w-2xl mx-auto">
            A simple, four-step process to protect your organization from API key theft
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, index) => (
            <div key={index} className="relative">
              <div className="incident-card rounded-xl p-6 h-full">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-[#E09B3D]/20 rounded-lg flex items-center justify-center flex-shrink-0">
                    <step.icon className="w-5 h-5 text-[#E09B3D]" />
                  </div>
                  <div className="text-2xl font-bold text-[#E09B3D]/40">0{index + 1}</div>
                </div>
                <h3 className="text-lg font-semibold mb-2 text-[#023D50]">{step.title}</h3>
                <p className="text-[#456A77] text-sm">{step.description}</p>
              </div>
              {index < steps.length - 1 && (
                <div className="hidden lg:block absolute top-1/2 -right-4 w-8 h-0.5 bg-gradient-to-r from-[#E09B3D]/50 to-transparent" />
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}