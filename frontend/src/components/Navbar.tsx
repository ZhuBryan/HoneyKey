import { Link, useLocation } from 'react-router-dom';

export function Navbar() {
  const location = useLocation();
  
  return (
    <nav className="bg-white border-b border-[#D4C4B0] sticky top-0 z-50 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-3 group">
            <img src="/HoneyKey Default Logo No Text.svg" alt="HoneyKey" className="h-10 w-10 group-hover:scale-105 transition-transform" />
            <span className="text-2xl font-bold text-[#023D50]">HoneyKey</span>
          </Link>
          
          <div className="flex items-center gap-6">
            <Link 
              to="/" 
              className={`transition-colors ${location.pathname === '/' ? 'text-[#E09B3D] font-medium' : 'text-[#456A77] hover:text-[#E09B3D]'}`}
            >
              Dashboard
            </Link>
            
            <Link 
              to="/reports" 
              className={`transition-colors ${location.pathname === '/reports' ? 'text-[#E09B3D] font-medium' : 'text-[#456A77] hover:text-[#E09B3D]'}`}
            >
              Reports
            </Link>
            
            <Link 
              to="/about" 
              className={`transition-colors ${location.pathname === '/about' ? 'text-[#E09B3D] font-medium' : 'text-[#456A77] hover:text-[#E09B3D]'}`}
            >
              About
            </Link>
          </div>
        </div>
      </div>
    </nav>
  );
}