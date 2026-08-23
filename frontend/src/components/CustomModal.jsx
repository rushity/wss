import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

export const CustomModal = ({ isOpen, onClose, title, description, children, footer, maxWidth = "max-w-md" }) => {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4 sm:p-0">
      <div 
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />
      
      <div className={`bg-surface-container-lowest border border-outline-variant shadow-2xl rounded-2xl w-full ${maxWidth} relative z-10 animate-fade-in flex flex-col max-h-[90vh] hide-scrollbar`}>
        
        {/* Header */}
        <div className={`flex justify-between items-start p-xl ${children ? 'border-b border-outline-variant' : ''}`}>
          <div className="pr-md">
            <h3 className="font-headline-sm font-bold text-on-surface text-[18px]">{title}</h3>
            {description && <p className="text-on-surface-variant font-body-sm text-[13px] mt-1">{description}</p>}
          </div>
          <button 
            onClick={onClose}
            className="text-on-surface-variant hover:text-on-surface hover:bg-surface-container p-2 rounded-full transition-colors border-0 bg-transparent cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        {children && (
          <div className="p-xl overflow-y-auto hide-scrollbar">
            {children}
          </div>
        )}

        {/* Footer */}
        {footer && (
          <div className={`flex justify-end gap-sm rounded-b-2xl ${children ? 'p-xl border-t border-outline-variant bg-surface-container-lowest' : 'px-xl pb-xl pt-0'}`}>
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body
  );
};
