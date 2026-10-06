import { createRoot } from 'react-dom/client';
import Home from './app/page';
import './app/globals.css';

const container = document.getElementById('root');
if (!container) throw new Error('Missing application root');
createRoot(container).render(<Home />);
