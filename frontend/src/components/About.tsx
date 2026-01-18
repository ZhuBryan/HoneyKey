import { Shield, Eye, Bell, FileText, ArrowRight, CheckCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

const fadeInUp = {
  initial: { opacity: 0, y: 60 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { margin: "-100px" },
  transition: { duration: 0.6 }
};

const staggerContainer = {
  initial: {},
  whileInView: { transition: { staggerChildren: 0.1 } },
  viewport: { margin: "-100px" }
};

export function About() {
  return (
    <div className="bg-[#FBEAD2]">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-32">
          <div className="text-center max-w-4xl mx-auto">
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center gap-2 bg-white border border-[#D4C4B0] rounded-full px-4 py-2 mb-8"
            >
              <Shield className="w-4 h-4 text-[#E09B3D]" />
              <span className="text-sm text-[#023D50] font-medium">AI-Powered API Security</span>
            </motion.div>
            
            <motion.h1 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="text-5xl sm:text-6xl lg:text-7xl font-bold mb-8 leading-tight text-[#023D50]"
            >
              Detect API Key Theft<br />
              <span className="gradient-text">Before It's Too Late</span>
            </motion.h1>
            
            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="text-xl text-[#456A77] mb-12 max-w-3xl mx-auto leading-relaxed"
            >
              Deploy intelligent honeypot API keys that automatically detect unauthorized access 
              and generate comprehensive security reports powered by AI.
            </motion.p>
            
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              className="flex items-center justify-center gap-4"
            >
              <Link
                to="/"
                className="inline-flex items-center gap-2 px-6 py-3 bg-[#023D50] hover:bg-[#034d64] text-white rounded-lg font-medium transition-all hover:scale-105"
              >
                View Live Dashboard
                <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                to="/reports"
                className="inline-flex items-center gap-2 px-6 py-3 bg-white border-2 border-[#023D50] hover:bg-[#FFF8F0] text-[#023D50] rounded-lg font-medium transition-all hover:scale-105"
              >
                View Sample Reports
              </Link>
            </motion.div>
          </div>
        </div>
        
        {/* Gradient decoration */}
        <div className="absolute inset-0 -z-10">
          <motion.div 
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.2 }}
            className="absolute top-0 left-1/4 w-96 h-96 bg-[#E09B3D]/10 rounded-full blur-3xl"
          ></motion.div>
          <motion.div 
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.2, delay: 0.2 }}
            className="absolute bottom-0 right-1/4 w-96 h-96 bg-[#023D50]/5 rounded-full blur-3xl"
          ></motion.div>
        </div>
      </section>

      {/* Problem/Solution Section */}
      <section className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <motion.div {...fadeInUp}>
              <h2 className="text-4xl font-bold text-[#023D50] mb-6">
                The Hidden Cost of<br />API Key Leaks
              </h2>
              <p className="text-lg text-[#456A77] mb-6 leading-relaxed">
                Exposed API keys cost companies millions annually through data breaches, 
                unauthorized resource consumption, and regulatory penalties.
              </p>
              <motion.ul 
                variants={staggerContainer}
                initial="initial"
                whileInView="whileInView"
                viewport={{ once: true }}
                className="space-y-4"
              >
                {[
                  'Average breach costs $4.35M per incident',
                  'Keys exposed in public repositories daily',
                  'Automated bots scan for credentials 24/7',
                  'Detection often takes weeks or months'
                ].map((item, i) => (
                  <motion.li 
                    key={i}
                    variants={fadeInUp}
                    className="flex items-start gap-3"
                  >
                    <div className="w-6 h-6 rounded-full bg-[#DC5037]/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <span className="text-[#DC5037] text-sm">✕</span>
                    </div>
                    <span className="text-[#023D50]">{item}</span>
                  </motion.li>
                ))}
              </motion.ul>
            </motion.div>
            
            <motion.div 
              {...fadeInUp}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="bg-[#FBEAD2] rounded-2xl p-8 border-2 border-[#D4C4B0]"
            >
              <h3 className="text-2xl font-bold text-[#023D50] mb-6">HoneyKey Solution</h3>
              <p className="text-[#456A77] mb-6 leading-relaxed">
                Deploy realistic honeypot keys that blend with your infrastructure. 
                When attackers attempt to use them, you gain immediate visibility.
              </p>
              <motion.ul 
                variants={staggerContainer}
                initial="initial"
                whileInView="whileInView"
                viewport={{ once: true }}
                className="space-y-4"
              >
                {[
                  'Instant detection of unauthorized access',
                  'AI-powered threat analysis',
                  'Automated security reports',
                  'Zero impact on production systems'
                ].map((item, i) => (
                  <motion.li 
                    key={i}
                    variants={fadeInUp}
                    className="flex items-start gap-3"
                  >
                    <CheckCircle className="w-6 h-6 text-[#16A085] flex-shrink-0 mt-0.5" />
                    <span className="text-[#023D50]">{item}</span>
                  </motion.li>
                ))}
              </motion.ul>
            </motion.div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-24 bg-[#FBEAD2]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div {...fadeInUp} className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4 text-[#023D50]">
              How It Works
            </h2>
            <p className="text-xl text-[#456A77] max-w-2xl mx-auto">
              Four simple steps to comprehensive API security
            </p>
          </motion.div>
          
          <motion.div 
            variants={staggerContainer}
            initial="initial"
            whileInView="whileInView"
            viewport={{ margin: "-100px" }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8"
          >
            {[
              {
                icon: Shield,
                number: '01',
                title: 'Deploy Honeypots',
                description: 'Place realistic API keys in repositories, documentation, or test environments.'
              },
              {
                icon: Eye,
                number: '02',
                title: 'Monitor Usage',
                description: 'Track all access attempts with detailed behavioral and network data.'
              },
              {
                icon: Bell,
                number: '03',
                title: 'Detect Threats',
                description: 'AI analyzes patterns to identify malicious activity instantly.'
              },
              {
                icon: FileText,
                number: '04',
                title: 'Get Reports',
                description: 'Receive detailed actionable security insights and threat analysis.'
              }
            ].map((step, i) => (
              <motion.div 
                key={i}
                variants={fadeInUp}
                whileHover={{ y: -8, transition: { duration: 0.3 } }}
                className="relative"
              >
                <div className="bg-white rounded-xl p-8 border border-[#D4C4B0] hover:border-[#E09B3D] transition-all h-full">
                  <div className="text-5xl font-bold text-[#E09B3D]/20 mb-4">{step.number}</div>
                  <div className="w-12 h-12 bg-[#E09B3D]/10 rounded-lg flex items-center justify-center mb-4">
                    <step.icon className="w-6 h-6 text-[#E09B3D]" />
                  </div>
                  <h3 className="text-xl font-semibold mb-3 text-[#023D50]">{step.title}</h3>
                  <p className="text-[#456A77] leading-relaxed">{step.description}</p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 bg-white">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div {...fadeInUp}>
            <h2 className="text-4xl font-bold mb-6 text-[#023D50]">
              Ready to Secure Your API Keys?
            </h2>
            <p className="text-xl text-[#456A77] mb-10 leading-relaxed">
              See HoneyKey in action with live incident detection and AI-powered security analysis.
            </p>
            <motion.div
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Link
                to="/"
                className="inline-flex items-center gap-2 px-8 py-4 bg-[#E09B3D] hover:bg-[#D4881C] text-white rounded-lg text-lg font-semibold transition-all shadow-lg hover:shadow-xl"
              >
                View Live Dashboard
                <ArrowRight className="w-5 h-5" />
              </Link>
            </motion.div>
          </motion.div>
        </div>
      </section>
    </div>
  );
}