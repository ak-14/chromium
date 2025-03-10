// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printing/print_job_constants.h"

#include "printing/buildflags/buildflags.h"

namespace printing {

// True if this is the first preview request.
const char kIsFirstRequest[] = "isFirstRequest";

// Unique ID sent along every preview request.
const char kPreviewRequestID[] = "requestID";

// Unique ID to identify a print preview UI.
const char kPreviewUIID[] = "previewUIID";

// Capabilities option. Contains the capabilities in CDD format.
const char kSettingCapabilities[] = "capabilities";

// Print using cloud print: true if selected, false if not.
const char kSettingCloudPrintId[] = "cloudPrintID";

// Print using cloud print dialog: true if selected, false if not.
const char kSettingCloudPrintDialog[] = "printWithCloudPrint";

// Print job setting 'collate'.
const char kSettingCollate[] = "collate";

// Print out color: true for color, false for grayscale.
const char kSettingColor[] = "color";

// Default to color on or not.
const char kSettingSetColorAsDefault[] = "setColorAsDefault";

// Key that specifies the height of the content area of the page.
const char kSettingContentHeight[] = "contentHeight";

// Key that specifies the width of the content area of the page.
const char kSettingContentWidth[] = "contentWidth";

// Number of copies.
const char kSettingCopies[] = "copies";

// Device name: Unique printer identifier.
const char kSettingDeviceName[] = "deviceName";

// Option to disable scaling. True if scaling is disabled else false.
const char kSettingDisableScaling[] = "disableScaling";

// Horizontal DPI
const char kSettingDpiHorizontal[] = "dpiHorizontal";

// Vertical DPI
const char kSettingDpiVertical[] = "dpiVertical";

// Scaling value required to fit the document to page.
const char kSettingFitToPageScaling[] = "fitToPageScaling";

// Print job duplex mode.
const char kSettingDuplexMode[] = "duplex";

// Option to fit source page contents to printer paper size: true if
// selected else false.
const char kSettingFitToPageEnabled[] = "fitToPageEnabled";

// True, when a new set of draft preview data is required.
const char kSettingGenerateDraftData[] = "generateDraftData";

// Option to print headers and Footers: true if selected, false if not.
const char kSettingHeaderFooterEnabled[] = "headerFooterEnabled";

// Interstice or gap between different header footer components. Hardcoded to
// about 0.5cm, match the value in PrintSettings::SetPrinterPrintableArea.
const float kSettingHeaderFooterInterstice = 14.2f;

// Key that specifies the date of the page that will be printed in the headers
// and footers.
const char kSettingHeaderFooterDate[] = "date";

// Key that specifies the title of the page that will be printed in the headers
// and footers.
const char kSettingHeaderFooterTitle[] = "title";

// Key that specifies the URL of the page that will be printed in the headers
// and footers.
const char kSettingHeaderFooterURL[] = "url";

// Page orientation: true for landscape, false for portrait.
const char kSettingLandscape[] = "landscape";

// Key that specifies the requested media size.
const char kSettingMediaSize[] = "mediaSize";

// Key that specifies the requested media height in microns.
const char kSettingMediaSizeHeightMicrons[] = "height_microns";

// Key that specifies the requested media width in microns.
const char kSettingMediaSizeWidthMicrons[] = "width_microns";

// Key that specifies the requested media platform specific vendor id.
const char kSettingMediaSizeVendorId[] = "vendor_id";

// Key that specifies whether the requested media is a default one.
const char kSettingMediaSizeIsDefault[] = "is_default";

// Key that specifies the bottom margin of the page.
const char kSettingMarginBottom[] = "marginBottom";

// Key that specifies the left margin of the page.
const char kSettingMarginLeft[] = "marginLeft";

// Key that specifies the right margin of the page.
const char kSettingMarginRight[] = "marginRight";

// Key that specifies the top margin of the page.
const char kSettingMarginTop[] = "marginTop";

// Key that specifies the dictionary of custom margins as set by the user.
const char kSettingMarginsCustom[] = "marginsCustom";

// Key that specifies the type of margins to use.  Value is an int from the
// MarginType enum.
const char kSettingMarginsType[] = "marginsType";

// Number of pages to print.
const char kSettingPreviewPageCount[] = "pageCount";

// A page range.
const char kSettingPageRange[] = "pageRange";

// The first page of a page range. (1-based)
const char kSettingPageRangeFrom[] = "from";

// The last page of a page range. (1-based)
const char kSettingPageRangeTo[] = "to";

// Page size of document to print.
const char kSettingPageWidth[] = "pageWidth";
const char kSettingPageHeight[] = "pageHeight";

const char kSettingPreviewModifiable[] = "previewModifiable";

// Keys that specifies the printable area details.
const char kSettingPrintableAreaX[] = "printableAreaX";
const char kSettingPrintableAreaY[] = "printableAreaY";
const char kSettingPrintableAreaWidth[] = "printableAreaWidth";
const char kSettingPrintableAreaHeight[] = "printableAreaHeight";

// Printer name.
const char kSettingPrinterName[] = "printerName";

// Printer description.
const char kSettingPrinterDescription[] = "printerDescription";

// Additional printer options.
const char kSettingPrinterOptions[] = "printerOptions";

// Print to PDF option: true if selected, false if not.
const char kSettingPrintToPDF[] = "printToPDF";

// Print using Privet option: true if destination is a Privet printer, false if
// not.
const char kSettingPrintWithPrivet[] = "printWithPrivet";

// Print using extension option: true if destination is an extension printer,
// false if not.
const char kSettingPrintWithExtension[] = "printWithExtension";

// Scaling factor
const char kSettingScaleFactor[] = "scaleFactor";

// Whether to rasterize the PDF for printing.
const char kSettingRasterizePdf[] = "rasterizePDF";

// Ticket option. Contains the ticket in CJT format.
const char kSettingTicket[] = "ticket";

// Whether to print CSS backgrounds.
const char kSettingShouldPrintBackgrounds[] = "shouldPrintBackgrounds";

// Whether to print selection only.
const char kSettingShouldPrintSelectionOnly[] = "shouldPrintSelectionOnly";

// Whether to print using the system dialog.
const char kSettingShowSystemDialog[] = "showSystemDialog";

// Indices used to represent first preview page and complete preview document.
const int FIRST_PAGE_INDEX = 0;
const int COMPLETE_PREVIEW_DOCUMENT_INDEX = -1;

// Whether to show PDF in view provided by OS. Implemented for MacOS only.
const char kSettingOpenPDFInPreview[] = "OpenPDFInPreview";

#if defined (USE_CUPS)
const char kBlack[] = "Black";
const char kCMYK[] = "CMYK";
const char kKCMY[] = "KCMY";
const char kCMY_K[] = "CMY+K";
const char kCMY[] = "CMY";
const char kColor[] = "Color";
const char kFullColor[] = "FullColor";
const char kGray[] = "Gray";
const char kGrayscale[] = "Grayscale";
const char kGreyscale[] = "Greyscale";
const char kMono[] = "Mono";
const char kMonochrome[] = "Monochrome";
const char kNormal[] = "Normal";
const char kNormalGray[] = "Normal.Gray";
const char kRGB[] = "RGB";
const char kRGBA[] = "RGBA";
const char kRGB16[] = "RGB16";
#endif

}  // namespace printing
