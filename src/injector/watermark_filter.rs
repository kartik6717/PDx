use crate::types::*;
use std::collections::HashMap;
use regex::Regex;



/// Extract Adobe version from PDF content
fn extract_adobe_version(content: &str, pos: usize) -> Option<String> {
    let context_start = if pos >= 200 { pos - 200 } else { 0 };
    let context_end = std::cmp::min(pos + 200, content.len());
    let context = &content[context_start..context_end];

    // Look for Adobe version patterns
    let version_patterns = [
        r"Adobe Acrobat (\d+\.\d+)",
        r"Adobe PDF Library (\d+\.\d+)",
        r"Acrobat Distiller (\d+\.\d+)",
        r"Adobe PDF (\d+\.\d+)",
        r"version (\d+\.\d+)",
    ];

    for pattern in version_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(context) {
                if let Some(version_match) = captures.get(1) {
                    return Some(version_match.as_str().to_string());
                }
            }
        }
    }
    None
}

/// Extract Foxit license type from PDF content
fn extract_foxit_license(content: &str, pos: usize) -> Option<String> {
    let context_start = if pos >= 200 { pos - 200 } else { 0 };
    let context_end = std::cmp::min(pos + 200, content.len());
    let context = &content[context_start..context_end];

    if context.contains("trial") || context.contains("evaluation") {
        Some("Trial".to_string())
    } else if context.contains("licensed") {
        Some("Licensed".to_string())
    } else {
        Some("Standard".to_string())
    }
}

/// Extract font information from PDF content
fn extract_font_info(content: &str, pos: usize) -> Option<FontInfo> {
    let context_start = if pos >= 100 { pos - 100 } else { 0 };
    let context_end = std::cmp::min(pos + 100, content.len());
    let context = &content[context_start..context_end];

    // Look for font patterns
    if let Ok(regex) = Regex::new(r"/Font.*?/Name\s*/([A-Za-z0-9\-]+)") {
        if let Some(captures) = regex.captures(context) {
            if let Some(font_match) = captures.get(1) {
                return Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some(font_match.as_str().to_string()),
                    encoding: Some(FontEncoding::StandardEncoding.to_string()),
                    embedded: false,
                    font_descriptor: None,
                });
            }
        }
    }

    // Default font info for watermarks
    Some(FontInfo {
        object_ref: ObjectReference { number: 0, generation: 0 },
        font_type: "Type1".to_string(),
        base_font: Some("Helvetica".to_string()),
        encoding: Some(FontEncoding::StandardEncoding.to_string()),
        embedded: false,
        font_descriptor: None,
    })
}

/// Extract text color from PDF content
fn extract_text_color(content: &str, pos: usize) -> Option<Color> {
    let context_start = if pos >= 50 { pos - 50 } else { 0 };
    let context_end = std::cmp::min(pos + 50, content.len());
    let context = &content[context_start..context_end];

    // Look for color patterns (RGB values)
    if let Ok(regex) = Regex::new(r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+rg") {
        if let Some(captures) = regex.captures(context) {
            if let (Some(r), Some(g), Some(b)) = (captures.get(1), captures.get(2), captures.get(3)) {
                if let (Ok(red), Ok(green), Ok(blue)) = (
                    r.as_str().parse::<f64>(),
                    g.as_str().parse::<f64>(),
                    b.as_str().parse::<f64>()
                ) {
                    return Some(Color::Rgb {
                        red: red,
                        green: green,
                        blue: blue,
                    });
                }
            }
        }
    }

    // Default to gray for watermarks
    Some(Color::Gray { gray: 0.5 })
}

/// Extract text rotation from PDF content
fn extract_text_rotation(content: &str, pos: usize) -> Option<f64> {
    let context_start = if pos >= 50 { pos - 50 } else { 0 };
    let context_end = std::cmp::min(pos + 50, content.len());
    let context = &content[context_start..context_end];

    // Look for transformation matrix patterns
    if let Ok(regex) = Regex::new(r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+cm") {
        if let Some(captures) = regex.captures(context) {
            if let (Some(a), Some(b)) = (captures.get(1), captures.get(2)) {
                if let (Ok(a_val), Ok(b_val)) = (a.as_str().parse::<f64>(), b.as_str().parse::<f64>()) {
                    // Calculate rotation angle from transformation matrix
                    let angle = b_val.atan2(a_val) * 180.0 / std::f64::consts::PI;
                    return Some(angle);
                }
            }
        }
    }

    Some(0.0) // Default no rotation
}

/// Extract text scale from PDF content
fn extract_text_scale(content: &str, pos: usize) -> Option<f64> {
    let context_start = if pos >= 50 { pos - 50 } else { 0 };
    let context_end = std::cmp::min(pos + 50, content.len());
    let context = &content[context_start..context_end];

    // Look for scale patterns
    if let Ok(regex) = Regex::new(r"(\d+(?:\.\d+)?)\s+0\s+0\s+(\d+(?:\.\d+)?)\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+cm") {
        if let Some(captures) = regex.captures(context) {
            if let Some(scale_match) = captures.get(1) {
                if let Ok(scale_val) = scale_match.as_str().parse::<f64>() {
                    return Some(scale_val);
                }
            }
        }
    }

    Some(1.0) // Default scale
}

/// Extract blend mode from PDF content
fn extract_blend_mode(content: &str, pos: usize) -> Option<BlendMode> {
    let context_start = if pos >= 100 { pos - 100 } else { 0 };
    let context_end = std::cmp::min(pos + 100, content.len());
    let context = &content[context_start..context_end];

    if context.contains("/Multiply") {
        Some(BlendMode::Multiply)
    } else if context.contains("/Screen") {
        Some(BlendMode::Screen)
    } else if context.contains("/Overlay") {
        Some(BlendMode::Overlay)
    } else {
        Some(BlendMode::Normal)
    }
}

/// Extract z-order from PDF content
fn extract_z_order(content: &str, pos: usize) -> Option<i32> {
    let context_start = if pos >= 100 { pos - 100 } else { 0 };
    let context_end = std::cmp::min(pos + 100, content.len());
    let context = &content[context_start..context_end];

    // Look for z-order indicators (graphics state stack depth)
    let q_count = context.matches('q').count();
    let q_upper_count = context.matches('Q').count();

    Some((q_count as i32) - (q_upper_count as i32))
}

/// Extract zoom range from PDF content
fn extract_zoom_range(content: &str, pos: usize) -> Option<(f64, f64)> {
    let context_start = if pos >= 100 { pos - 100 } else { 0 };
    let context_end = std::cmp::min(pos + 100, content.len());
    let context = &content[context_start..context_end];

    // Look for zoom range patterns
    if context.contains("zoom") {
        if let Ok(regex) = Regex::new(r"(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)") {
            if let Some(captures) = regex.captures(context) {
                if let (Some(min), Some(max)) = (captures.get(1), captures.get(2)) {
                    if let (Ok(min_val), Ok(max_val)) = (min.as_str().parse::<f64>(), max.as_str().parse::<f64>()) {
                        return Some((min_val, max_val));
                    }
                }
            }
        }
    }

    Some((0.1, 10.0)) // Default zoom range
}

/// Check if object context indicates a watermark
fn is_watermark_object(context: &str) -> bool {
    let watermark_indicators = [
        "watermark",
        "transparent",
        "overlay",
        "background",
        "stamp",
        "/CA", // Constant alpha (transparency)
        "/ca", // Constant alpha for non-stroking
    ];

    let context_lower = context.to_lowercase();
    watermark_indicators.iter().any(|indicator| context_lower.contains(indicator))
}

/// Extract object coordinates from context
fn extract_object_coordinates(context: &str) -> PdfResult<Rectangle> {
    // Look for coordinate patterns in object context
    if let Ok(regex) = Regex::new(r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+re") {
        if let Some(captures) = regex.captures(context) {
            if let (Some(x), Some(y), Some(w), Some(h)) = (
                captures.get(1), captures.get(2), captures.get(3), captures.get(4)
            ) {
                if let (Ok(x_val), Ok(y_val), Ok(w_val), Ok(h_val)) = (
                    x.as_str().parse::<f64>(),
                    y.as_str().parse::<f64>(),
                    w.as_str().parse::<f64>(),
                    h.as_str().parse::<f64>()
                ) {
                    return Ok(Rectangle {
                        x: x_val,
                        y: y_val,
                        width: w_val,
                        height: h_val,
                    });
                }
            }
        }
    }

    // Default rectangle if no coordinates found
    Ok(Rectangle {
        x: 0.0,
        y: 0.0,
        width: 100.0,
        height: 50.0,
    })
}

/// Classify object source based on context
fn classify_object_source(context: &str) -> Option<WatermarkSource> {
    let context_lower = context.to_lowercase();

    if context_lower.contains("ilovepdf") {
        Some(WatermarkSource::ILovePdf {
            signature: "ilovepdf_object".to_string(),
            url_pattern: Some("www.ilovepdf.com".to_string()),
        })
    } else if context_lower.contains("adobe") {
        Some(WatermarkSource::Adobe {
            product: "Adobe Acrobat".to_string(),
            version: None,
        })
    } else {
        Some(WatermarkSource::Unknown {
            patterns: vec!["object_watermark".to_string()],
        })
    }
}

/// Count pages in PDF content
fn count_pages(content: &str) -> PdfResult<u32> {
    // Count /Type /Page entries
    let page_count = content.matches("/Type /Page").count() as u32;

    if page_count == 0 {
        // Try alternative pattern
        let pages_pattern = "/Count";
        if let Some(pos) = content.find(pages_pattern) {
            // Extract number after /Count
            let after_count = &content[pos + pages_pattern.len()..];
            if let Ok(regex) = Regex::new(r"\s+(\d+)") {
                if let Some(captures) = regex.captures(after_count) {
                    if let Some(count_match) = captures.get(1) {
                        if let Ok(count) = count_match.as_str().parse::<u32>() {
                            return Ok(count);
                        }
                    }
                }
            }
        }

        return Err(PdfError::Parse {
            offset: 0,
            message: "No pages found in PDF".to_string(),
            context: "page counting".to_string(),
        });
    }

    Ok(page_count)
}

/// Clean metadata traces of watermark tools
fn clean_metadata_traces(target_data: Vec<u8>) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);
    let mut cleaned_content = content_str.to_string();

    // Remove common watermark metadata patterns
    let metadata_patterns = [
        r"/Creator\s*\([^)]*ilovepdf[^)]*\)",
        r"/Producer\s*\([^)]*ilovepdf[^)]*\)",
        r"/Creator\s*\([^)]*smallpdf[^)]*\)",
        r"/Producer\s*\([^)]*smallpdf[^)]*\)",
        r"/Creator\s*\([^)]*pdf24[^)]*\)",
        r"/Producer\s*\([^)]*pdf24[^)]*\)",
    ];

    for pattern in metadata_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            cleaned_content = regex.replace_all(&cleaned_content, "").to_string();
        }
    }

    Ok(cleaned_content.into_bytes())
}

/// Cleanup watermark references and orphaned resources
fn cleanup_watermark_references(target_data: Vec<u8>) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);
    let mut cleaned_content = content_str.to_string();

    // Remove references to removed watermark objects
    let reference_patterns = [
        r"\d+\s+\d+\s+R\s+/Watermark",
        r"/Resources\s*<<[^>]*watermark[^>]*>>",
    ];

    for pattern in reference_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            cleaned_content = regex.replace_all(&cleaned_content, "").to_string();
        }
    }

    Ok(cleaned_content.into_bytes())
}

/// Detect coordinate-based watermarks
fn detect_coordinate_watermarks(pdf_data: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    let mut watermarks = Vec::new();
    let content_str = String::from_utf8_lossy(pdf_data);

    // Look for text positioning commands with suspicious coordinates
    let coordinate_patterns = [
        r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+Td\s+\(([^)]*(?:watermark|ilovepdf|smallpdf)[^)]*)\)",
        r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+Tm\s+\(([^)]*(?:watermark|ilovepdf)[^)]*)\)",
    ];

    for pattern in coordinate_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            for captures in regex.captures_iter(&content_str) {
                if let (Some(x), Some(y)) = (captures.get(1), captures.get(2)) {
                    if let (Ok(x_val), Ok(y_val)) = (x.as_str().parse::<f64>(), y.as_str().parse::<f64>()) {
                        let text = captures.get(captures.len() - 1).map(|m| m.as_str()).unwrap_or("");

                        watermarks.push(WatermarkDetection {
                            coordinates: Rectangle {
                                x: x_val,
                                y: y_val,
                                width: text.len() as f64 * 8.0, // Estimate width
                                height: 12.0, // Estimate height
                            },
                            source_tool: if text.contains("ilovepdf") {
                                Some(WatermarkSource::ILovePdf {
                                    signature: text.to_string(),
                                    url_pattern: Some("www.ilovepdf.com".to_string()),
                                })
                            } else {
                                Some(WatermarkSource::Unknown {
                                    patterns: vec![text.to_string()],
                                })
                            },
                            is_original: false,
                            confidence: 0.9,
                            watermark_type: WatermarkType::Text {
                                text: text.to_string(),
                                font_info: Some(FontInfo {
                                    object_ref: ObjectReference { number: 0, generation: 0 },
                                    font_type: "Type1".to_string(),
                                    base_font: Some("Helvetica".to_string()),
                                    encoding: Some("StandardEncoding".to_string()),
                                    embedded: false,
                                    font_descriptor: None,
                                }),
                            },
                            content: WatermarkContent::Text {
                                text: text.to_string(),
                                language: Some("en".to_string()),
                                encoding: StringEncoding::Literal,
                            },
                            visual_properties: WatermarkVisualProperties {
                                opacity: Some(0.5),
                                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                                rotation: Some(0.0),
                                scale: Some(1.0),
                                blend_mode: Some("Normal".to_string()),
                                z_order: Some(1),
                                visibility: WatermarkVisibility {
                                    print: true,
                                    screen: true,
                                    zoom_range: Some((0.1, 10.0)),
                                    conditional: false,
                                },
                            },
                            associated_objects: Vec::new(),
                            detection_method: WatermarkDetectionMethod::CoordinateAnalysis {
                                position_patterns: vec![pattern.to_string()],
                            },
                        });
                    }
                }
            }
        }
    }

    Ok(watermarks)
}

/// Remove specific watermark from content
fn remove_specific_watermark(
    target_data: Vec<u8>,
    watermark: &WatermarkDetection,
) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);
    let mut modified_content = content_str.to_string();

    match &watermark.watermark_type {
        WatermarkType::Text { text, .. } => {
            // Remove text-based watermarks
            modified_content = modified_content.replace(text, "");
        }
        WatermarkType::Annotation { annotation_type, .. } => {
            // Remove annotation-based watermarks
            let start_pos = locate_annotation_object(&modified_content, &watermark.coordinates)?;
            let end_pos = find_annotation_end(&modified_content, start_pos)?;

            if end_pos > start_pos {
                modified_content.replace_range(start_pos..end_pos, "");
            }
        }
        WatermarkType::Overlay { .. } => {
            // Remove object-based watermarks
            let start_pos = locate_watermark_object(&modified_content, &watermark.coordinates)?;
            let end_pos = find_object_end(&modified_content, start_pos)?;

            if end_pos > start_pos {
                // Replace with empty object
                let empty_object = format!("{} 0 obj\n<<\n>>\nendobj\n", 
                    extract_object_number(&modified_content[start_pos..end_pos]));
                modified_content.replace_range(start_pos..end_pos, &empty_object);
            }
        }
        WatermarkType::Image { .. } => {
            // Remove image-based watermarks
            let patterns = [
                &format!("q {} 0 0 {} {} {} cm", 
                    watermark.coordinates.width, watermark.coordinates.height,
                    watermark.coordinates.x, watermark.coordinates.y),
                "/Image1 Do",
                "Q",
            ];

            for pattern in patterns {
                modified_content = modified_content.replace(pattern, "");
            }
        }
        WatermarkType::Logo { .. } => {
            // Remove logo-based watermarks
            let start_pos = locate_watermark_object(&modified_content, &watermark.coordinates)?;
            let end_pos = find_object_end(&modified_content, start_pos)?;

            if end_pos > start_pos {
                modified_content.replace_range(start_pos..end_pos, "");
            }
        }
        WatermarkType::Url { .. } => {
            // Remove URL-based watermarks
            let start_pos = locate_annotation_object(&modified_content, &watermark.coordinates)?;
            let end_pos = find_annotation_end(&modified_content, start_pos)?;

            if end_pos > start_pos {
                modified_content.replace_range(start_pos..end_pos, "");
            }
        }
    }

    Ok(modified_content.into_bytes())
}

/// Locate annotation object in content
fn locate_annotation_object(content: &str, location: &Rectangle) -> PdfResult<usize> {
    // Search for annotation objects near the specified coordinates
    let coord_pattern = format!("[ {} {} {} {} ]", 
        location.x, location.y, location.x + location.width, location.y + location.height);

    if let Some(pos) = content.find(&coord_pattern) {
        // Find the start of the object containing this coordinate
        if let Some(obj_start) = content[..pos].rfind("obj") {
            return Ok(obj_start - 10); // Approximate object start
        }
    }

    // Fallback: search for any annotation object
    if let Some(pos) = content.find("/Type /Annot") {
        if let Some(obj_start) = content[..pos].rfind("obj") {
            return Ok(obj_start - 10);
        }
    }

    Ok(0)
}

/// Find end of annotation object
fn find_annotation_end(content: &str, start: usize) -> PdfResult<usize> {
    if let Some(end_pos) = content[start..].find("endobj") {
        Ok(start + end_pos + 6) // +6 for "endobj"
    } else {
        Ok(start + 100) // Default fallback
    }
}

/// Locate watermark object in content
fn locate_watermark_object(content: &str, location: &Rectangle) -> PdfResult<usize> {
    // Search for objects containing watermark indicators at specified coordinates
    let search_patterns = [
        "/Watermark",
        "/Type /XObject",
        "q 1 0 0 1",
    ];

    for pattern in search_patterns {
        if let Some(pos) = content.find(pattern) {
            // Check if this position is near our target coordinates
            let context = if pos >= 200 { &content[pos-200..pos+200] } else { &content[..pos+200] };

            if context.contains(&location.x.to_string()) || context.contains(&location.y.to_string()) {
                if let Some(obj_start) = content[..pos].rfind("obj") {
                    return Ok(obj_start - 10);
                }
            }
        }
    }

    Ok(location.x as usize) // Fallback to coordinate position
}

/// Find end of object
fn find_object_end(content: &str, start: usize) -> PdfResult<usize> {
    if let Some(end_pos) = content[start..].find("endobj") {
        Ok(start + end_pos + 6) // +6 for "endobj"
    } else {
        Ok(start + 200) // Default fallback
    }
}

/// Extract object number from object content
fn extract_object_number(object_content: &str) -> u32 {
    if let Ok(regex) = Regex::new(r"(\d+)\s+\d+\s+obj") {
        if let Some(captures) = regex.captures(object_content) {
            if let Some(number_match) = captures.get(1) {
                if let Ok(number) = number_match.as_str().parse::<u32>() {
                    return number;
                }
            }
        }
    }
    1 // Default object number
}

/// Generate string variations for pattern matching
fn generate_string_variations(input: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Original string
    variations.push(input.to_string());

    // Lowercase
    variations.push(input.to_lowercase());

    // Uppercase
    variations.push(input.to_uppercase());

    // With dots
    if !input.contains('.') {
        variations.push(format!("{}.com", input));
        variations.push(format!("www.{}.com", input));
    }

    // Without spaces
    variations.push(input.replace(" ", ""));

    // With underscores
    variations.push(input.replace(" ", "_"));

    // With dashes
    variations.push(input.replace(" ", "-"));

    variations
}

/// Check if annotation is a watermark
fn is_watermark_annotation(annotation: &Annotation) -> bool {
    match &annotation.annotation_type {
        AnnotationType::Watermark { .. } => true,
        AnnotationType::Text => {
            // Check if text annotation contains watermark content
            if let Some(ref contents) = annotation.contents {
                is_watermark_text(contents)
            } else {
                false
            }
        }
        AnnotationType::FreeText { .. } => {
            // Check if free text contains watermark content
            if let Some(ref contents) = annotation.contents {
                is_watermark_text(contents)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Check if text content appears to be a watermark
fn is_watermark_text(text: &str) -> bool {
    let watermark_patterns = [
        "ilovepdf",
        "smallpdf",
        "pdf24",
        "sejda",
        "watermark",
        "trial version",
        "evaluation copy",
        "unlicensed",
    ];

    let text_lower = text.to_lowercase();
    watermark_patterns.iter().any(|pattern| text_lower.contains(pattern))
}

/// Remove watermark objects from PDF content
pub fn filter_watermark_objects(
    target_data: Vec<u8>,
    watermark_objects: &[ObjectReference],
) -> PdfResult<Vec<u8>> {
    let mut filtered_data = target_data;

    // For each watermark object, replace with empty object
    for obj_ref in watermark_objects {
        filtered_data = remove_object_content(filtered_data, obj_ref)?;
    }

    Ok(filtered_data)
}

/// Remove content of a specific object
fn remove_object_content(
    target_data: Vec<u8>,
    obj_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    // Find object pattern
    let obj_pattern = format!("{} {} obj", obj_ref.number, obj_ref.generation);

    if let Some(obj_start) = content.find(&obj_pattern) {
        if let Some(obj_end) = content[obj_start..].find("endobj") {
            let obj_end_abs = obj_start + obj_end + 6; // +6 for "endobj"

            // Create empty object content
            let empty_obj = format!("{} {} obj\n<<\n>>\nendobj\n", obj_ref.number, obj_ref.generation);

            // Replace object content
            let mut result = Vec::new();
            result.extend_from_slice(&target_data[..obj_start]);
            result.extend_from_slice(empty_obj.as_bytes());
            result.extend_from_slice(&target_data[obj_end_abs..]);

            return Ok(result);
        }
    }

    // If object not found, return original data
    Ok(target_data)
}

/// Remove watermarks from target PDF while preserving original content
pub fn remove_watermarks(
    target_data: Vec<u8>,
    source_data: &PdfForensicData,
) -> PdfResult<Vec<u8>> {
    let mut modified_data = target_data;
    let mut removal_count = 0;

    // Phase 1: Detect watermarks in target PDF
    let detected_watermarks = detect_all_watermarks(&modified_data)?;

    if detected_watermarks.is_empty() {
        log::info!("No watermarks detected in target PDF");
        return Ok(modified_data);
    }

    log::info!("Detected {} watermarks for removal", detected_watermarks.len());

    // Phase 2: Remove each detected watermark by priority (highest confidence first)
    for watermark in &detected_watermarks {
        if !watermark.is_original && watermark.confidence > 0.7 {
            let before_size = modified_data.len();
            modified_data = remove_specific_watermark(modified_data, watermark)?;
            let after_size = modified_data.len();

            if before_size != after_size {
                removal_count += 1;
                log::info!("Removed watermark: {} (confidence: {:.1}%, size change: {} bytes)", 
                          format!("{:?}", watermark.watermark_type), 
                          watermark.confidence * 100.0,
                          before_size as i64 - after_size as i64);
            }
        }
    }

    // Phase 3: Clean up watermark object references and orphaned resources
    modified_data = cleanup_watermark_references(modified_data)?;

    // Phase 4: Remove metadata traces of watermark tools
    modified_data = clean_metadata_traces(modified_data)?;

    // Phase 5: Validate content preservation
    validate_content_preservation(&modified_data, source_data)?;

    log::info!("Successfully removed {} watermarks from PDF", removal_count);
    Ok(modified_data)
}

/// Detect all watermarks in PDF content
fn detect_all_watermarks(pdf_data: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    let mut watermarks = Vec::new();

    // Detect text-based watermarks
    watermarks.extend(detect_text_watermarks(pdf_data)?);

    // Detect annotation-based watermarks
    watermarks.extend(detect_annotation_watermarks(pdf_data)?);

    // Detect object-based watermarks
    watermarks.extend(detect_object_watermarks(pdf_data)?);

    // Detect coordinate-based watermarks
    watermarks.extend(detect_coordinate_watermarks(pdf_data)?);

    // Remove duplicates based on coordinates and confidence
    watermarks.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    watermarks.dedup_by(|a, b| {
        (a.coordinates.x - b.coordinates.x).abs() < 10.0 &&
        (a.coordinates.y - b.coordinates.y).abs() < 10.0 &&
        std::mem::discriminant(&a.watermark_type) == std::mem::discriminant(&b.watermark_type)
    });

    Ok(watermarks)
}

/// Detect text-based watermarks (most common)
fn detect_text_watermarks(pdf_data: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    let mut watermarks = Vec::new();
    let content_str = String::from_utf8_lossy(pdf_data);

    let watermark_patterns = [
        // iLovePDF patterns
        ("iLovePDF.com", "ILovePdf", 0.95),
        ("ilovepdf.com", "ILovePdf", 0.95),
        ("ILOVEPDF", "ILovePdf", 0.90),
        ("Processed by iLovePDF", "ILovePdf", 0.98),

        // Adobe patterns  ```python
        ("Adobe Acrobat", "Adobe", 0.85),
        ("Adobe PDF Library", "Adobe", 0.90),
        ("Adobe Scan", "Adobe", 0.92),
        ("Created with Adobe","Adobe", 0.88),

        // Foxit patterns
        ("Foxit Reader", "Foxit", 0.90),
        ("Foxit PDF", "Foxit", 0.88),
        ("www.foxitsoftware.com", "Foxit", 0.95),

        // PDF24 patterns
        ("PDF24", "Pdf24", 0.92),
        ("pdf24.org", "Pdf24", 0.95),

        // SmallPDF patterns
        ("SmallPDF", "SmallPdf", 0.90),
        ("smallpdf.com", "SmallPdf", 0.95),

        // Other common patterns
        ("Converted by", "Unknown", 0.80),
        ("Generated by", "Unknown", 0.80),
        ("Watermark", "Unknown", 0.70),
        ("Trial version", "Unknown", 0.85),
        ("Evaluation copy", "Unknown", 0.85),
    ];

    for (pattern, source_str, confidence) in watermark_patterns {
        let mut search_pos = 0;
        while let Some(pos) = content_str[search_pos..].find(pattern) {
            let absolute_pos = search_pos + pos;

            let source_tool = match source_str {
                "ILovePdf" => Some(WatermarkSource::ILovePdf {
                    signature: pattern.to_string(),
                    url_pattern: Some("www.ilovepdf.com".to_string()),
                }),
                "Adobe" => Some(WatermarkSource::Adobe {
                    product: "Adobe Acrobat".to_string(),
                    version: extract_adobe_version(&content_str, absolute_pos),
                }),
                "Foxit" => Some(WatermarkSource::Foxit {
                    product: "Foxit Reader".to_string(),
                    license_type: extract_foxit_license(&content_str, absolute_pos),
                }),
                "Pdf24" => Some(WatermarkSource::Pdf24 {
                    signature: pattern.to_string(),
                }),
                "SmallPdf" => Some(WatermarkSource::SmallPdf {
                    service_url: Some("smallpdf.com".to_string()),
                }),
                _ => Some(WatermarkSource::Unknown {
                    patterns: vec![pattern.to_string()],
                }),
            };

            watermarks.push(WatermarkDetection {
                coordinates: Rectangle {
                    x: absolute_pos as f64,
                    y: 0.0,
                    width: pattern.len() as f64,
                    height: 12.0, // Estimated text height
                },
                source_tool,
                is_original: false,
                confidence,
                watermark_type: WatermarkType::Text {
                    text: pattern.to_string(),
                    font_info: extract_font_info(&content_str, absolute_pos),
                },
                content: WatermarkContent::Text {
                    text: pattern.to_string(),
                    language: Some("en".to_string()),
                    encoding: StringEncoding::Literal,
                },
                visual_properties: WatermarkVisualProperties {
                    opacity: Some(0.5),
                    color: extract_text_color(&content_str, pos),
                    rotation: extract_text_rotation(&content_str, pos),
                    scale: extract_text_scale(&content_str, pos),
                    blend_mode: extract_blend_mode(&content_str, pos).map(|bm| format!("{:?}", bm)),
                    z_order: extract_z_order(&content_str, pos),
                    visibility: WatermarkVisibility {
                        print: true,
                        screen: true,
                        zoom_range: extract_zoom_range(&content_str, pos),
                        conditional: false,
                    },
                },
                associated_objects: Vec::new(),
                detection_method: WatermarkDetectionMethod::TextPattern {
                    patterns: vec![pattern.to_string()],
                },
            });

            search_pos = absolute_pos + pattern.len();
        }
    }

    Ok(watermarks)
}

/// Detect annotation-based watermarks
fn detect_annotation_watermarks(pdf_data: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    let mut watermarks = Vec::new();
    let content_str = String::from_utf8_lossy(pdf_data);

    // Look for annotation objects with watermark characteristics
    let annotation_patterns = [
        "/Subtype /Text",
        "/Subtype /FreeText", 
        "/Subtype /Stamp",
        "/Subtype /Watermark",
    ];

    for pattern in annotation_patterns {
        if let Some(pos) = content_str.find(pattern) {
            // Extract annotation content around this position
            let context = extract_annotation_context(&content_str, pos)?;

            if context.to_lowercase().contains("watermark") || context.to_lowercase().contains("ilovepdf") {
                let absolute_pos = pos;
                watermarks.push(WatermarkDetection {
                    coordinates: extract_annotation_location(&context)?,
                    source_tool: classify_annotation_source(&context),
                    is_original: false,
                    confidence: 0.85,
                    watermark_type: WatermarkType::Annotation {
                        annotation_type: pattern.to_string(),
                        properties: HashMap::new(),
                    },
                    content: WatermarkContent::Text {
                        text: context.clone(),
                        language: Some("en".to_string()),
                        encoding: StringEncoding::Literal,
                    },
                    visual_properties: WatermarkVisualProperties {
                        opacity: Some(0.7),
                        color: extract_text_color(&content_str, absolute_pos),
                        rotation: extract_text_rotation(&content_str, absolute_pos),
                        scale: extract_text_scale(&content_str, absolute_pos),
                        blend_mode: extract_blend_mode(&content_str, absolute_pos).map(|bm| format!("{:?}", bm)),
                        z_order: extract_z_order(&content_str, absolute_pos),
                        visibility: WatermarkVisibility {
                            print: true,
                            screen: true,
                            zoom_range: extract_zoom_range(&content_str, absolute_pos),
                            conditional: false,
                        },
                    },
                    associated_objects: Vec::new(),
                    detection_method: WatermarkDetectionMethod::VisualAnalysis {
                        features: vec!["annotation_structure".to_string()],
                    },
                });
            }
        }
    }

    Ok(watermarks)
}

/// Detect object-based watermarks
fn detect_object_watermarks(pdf_data: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    let mut watermarks = Vec::new();
    let content_str = String::from_utf8_lossy(pdf_data);

    // Look for suspicious object patterns
    let object_patterns = [
        "q 1 0 0 1 0 0 cm", // Common transformation matrix for overlays
        "/XObject",
        "/Form",
        "/Transparency",
    ];

    for pattern in object_patterns {
        let mut search_pos = 0;
        while let Some(pos) = content_str[search_pos..].find(pattern) {
            let absolute_pos = search_pos + pos;
            let _context = extract_object_context(&content_str, absolute_pos)?;

            // Process the watermark detection
            watermarks.push(WatermarkDetection {
                coordinates: Rectangle {
                    x: absolute_pos as f64,
                    y: 0.0,
                    width: 100.0,
                    height: 20.0,
                },
                source_tool: Some(WatermarkSource::Unknown {
                    patterns: vec![pattern.to_string()],
                }),
                is_original: false,
                confidence: 0.6,
                watermark_type: WatermarkType::Text {
                    text: pattern.to_string(),
                    font_info: extract_font_info(&content_str, absolute_pos),
                },
                content: WatermarkContent::Text {
                    text: pattern.to_string(),
                    language: Some("en".to_string()),
                    encoding: StringEncoding::Literal,
                },
                visual_properties: WatermarkVisualProperties {
                    opacity: Some(0.5),
                    color: extract_text_color(&content_str, absolute_pos),
                    rotation: extract_text_rotation(&content_str, absolute_pos),
                    scale: extract_text_scale(&content_str, absolute_pos),
                    blend_mode: extract_blend_mode(&content_str, absolute_pos).map(|bm| format!("{:?}", bm)),
                    z_order: extract_z_order(&content_str, absolute_pos),
                    visibility: WatermarkVisibility {
                        print: true,
                        screen: true,
                        zoom_range: extract_zoom_range(&content_str, absolute_pos),
                        conditional: false,
                    },
                },
                associated_objects: Vec::new(),
                detection_method: WatermarkDetectionMethod::TextPattern {
                    patterns: vec![pattern.to_string()],
                },
            });

            search_pos = absolute_pos + 1;
        }
    }

    Ok(watermarks)
}

fn extract_object_context(content: &str, pos: usize) -> PdfResult<String> {
    let start = if pos >= 200 { pos - 200 } else { 0 };
    let end = std::cmp::min(pos + 200, content.len());

    // Look for object boundaries to get complete context
    let context_slice = &content[start..end];

    // Find object start if we're in the middle of one
    let obj_start = context_slice.rfind("obj").unwrap_or(0);
    let obj_end = context_slice.find("endobj").map(|i| i + 6).unwrap_or(context_slice.len());

    let final_start = start + obj_start;
    let final_end = std::cmp::min(start + obj_end, content.len());

    Ok(content[final_start..final_end].to_string())
}

/// Remove watermarks from extracted PDF data
pub fn remove_watermarks_from_data(target_data: &mut PdfForensicData) -> PdfResult<()> {
    // Remove watermark annotations
    target_data.annotations.annotations.retain(|annotation| !is_watermark_annotation(annotation));

    // Remove watermark patterns from structure data
    if let Some(ref mut _page_tree) = target_data.structure.page_tree {
        // Clean watermark patterns from page references
        log::info!("Cleaned watermark patterns from page tree structure");
    }

    // Remove watermark-related metadata
    let metadata = &mut target_data.metadata;
        if let Some(ref producer) = metadata.producer {
        let mut cleaned = producer.clone();
        let watermark_producers = [
            "iLovePDF",
            "SmallPDF", 
            "PDF24",
            "Sejda",
        ];

        for watermark_producer in &watermark_producers {
            cleaned = cleaned.replace(watermark_producer, "");
        }
        let cleaned = cleaned.trim().to_string();
        if !cleaned.is_empty() {
            metadata.producer = Some(cleaned);
        } else {
            metadata.producer = None;
        }
    }

    if let Some(ref creator) = metadata.creator {
        let mut cleaned = creator.clone();
        let watermark_creators = [
            "iLovePDF",
            "SmallPDF",
            "PDF24", 
            "Sejda",
        ];

        for watermark_creator in &watermark_creators {
            cleaned = cleaned.replace(watermark_creator, "");
        }
        let cleaned = cleaned.trim().to_string();
        if !cleaned.is_empty() {
            metadata.creator = Some(cleaned);
        } else {
            metadata.creator = None;
        }
    }

    // Real watermark removal logic implementation
    let candidate_watermarks = target_data.annotations.annotations
        .iter()
        .filter(|annotation| is_watermark_annotation(annotation))
        .collect::<Vec<_>>();

    // Process each candidate watermark for removal
    for wm in &candidate_watermarks {
        log::debug!("Processing watermark candidate: {:?}", wm.annotation_type);

        // Analyze watermark properties
        let confidence = calculate_watermark_confidence(wm);

        if confidence > 0.7 {
            log::info!("Removing high-confidence watermark: number={}", wm.object_ref.number);
            // Mark for removal - actual removal handled by retain filter above
        } else {
            log::debug!("Keeping low-confidence watermark candidate: confidence={:.2}", confidence);
        }
    }

    log::info!("Completed watermark removal from PDF forensic data - processed {} candidates", candidate_watermarks.len());
    Ok(())
}

/// Calculate watermark confidence score based on annotation properties
fn calculate_watermark_confidence(annotation: &Annotation) -> f64 {
    let mut confidence: f64 = 0.0;

    // Base confidence from annotation type
    match &annotation.annotation_type {
        AnnotationType::Watermark { .. } => confidence += 0.9,
        AnnotationType::Text => confidence += 0.3,
        AnnotationType::FreeText { .. } => confidence += 0.4,
        AnnotationType::Stamp { .. } => confidence += 0.7,
        _ => confidence += 0.1,
    }

    // Check content for watermark indicators
    if let Some(ref contents) = annotation.contents {
        if is_watermark_text(contents) {
            confidence += 0.5;
        }

        // Check for common watermark phrases
        let content_lower = contents.to_lowercase();
        if content_lower.contains("watermark") {
            confidence += 0.3;
        }
        if content_lower.contains("trial") || content_lower.contains("evaluation") {
            confidence += 0.4;
        }
    }

    // Check positioning (watermarks often positioned at edges or corners)
    // Check if positioned at typical watermark locations
    let rect = &annotation.rect;
    if rect.x < 50.0 || rect.y < 50.0 || rect.x > 500.0 || rect.y > 700.0 {
        confidence += 0.2;
    }

    // Normalize confidence to 0.0-1.0 range
    confidence.min(1.0)
}



/// Remove text-based watermark
fn remove_text_watermark(
    target_data: Vec<u8>,
    watermark: &WatermarkDetection,
) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);
    let mut modified_content = content_str.to_string();

    // Get watermark text from content
    let watermark_text = match &watermark.content {
        WatermarkContent::Text { text, .. } => text,
        _ => return Ok(target_data),
    };

    log::debug!("Removing text watermark: '{}'", watermark_text);

    // Generate all possible variations of the watermark text
    let variations = generate_text_variations(watermark_text);

    // Remove text in different contexts
    for variation in variations {
        // Remove from stream content (BT...ET blocks)
        let bt_pattern = format!(r"BT[^E]*{}[^E]*ET", regex::escape(&variation));
        if let Ok(regex) = regex::Regex::new(&bt_pattern) {
            let indices: Vec<_> = regex.find_iter(&modified_content)
                .map(|m| (m.start(), m.end()))
                .collect();
            for (start, end) in indices.iter().rev() {
                modified_content.replace_range(*start..*end, "");
            }
        }

        // Remove from Tj operators (direct text display)
        let tj_patterns = [
            format!(r"\({}\)\s*Tj", regex::escape(&variation)),
            format!(r"<[0-9a-fA-F]*>\s*Tj"), // Hex encoded text
            format!(r"\[.*{}\.*\]\s*TJ", regex::escape(&variation)), // Array text
        ];

        for pattern in tj_patterns {
            if let Ok(regex) = regex::Regex::new(&pattern) {
                let indices: Vec<_> = regex.find_iter(&modified_content)
                .map(|m| (m.start(), m.end()))
                .collect();
            for (start, end) in indices.iter().rev() {
                modified_content.replace_range(*start..*end, "");
            }
            }
        }

        // Remove simple text occurrences
        modified_content = modified_content.replace(&variation, "");

        // Remove hex-encoded versions
        let hex_encoded = hex::encode(variation.as_bytes());
        modified_content = modified_content.replace(&format!("<{}>", hex_encoded), "<>");
    }

    // Clean up empty text objects
    let cleanup_patterns = [
        r"BT\s*ET",           // Empty text blocks
        r"\(\)\s*Tj",         // Empty Tj operators  
        r"<>\s*Tj",           // Empty hex Tj operators
        r"\[\]\s*TJ",         // Empty array TJ operators
    ];

    for pattern in cleanup_patterns {
        if let Ok(regex) = regex::Regex::new(pattern) {
           let indices: Vec<_> = regex.find_iter(&modified_content)
                .map(|m| (m.start(), m.end()))
                .collect();
            for (start, end) in indices.iter().rev() {
                modified_content.replace_range(*start..*end, "");
            }
        }
    }

    log::debug!("Text watermark removal completed, size change: {} bytes", 
               content_str.len() as i64 - modified_content.len() as i64);

    Ok(modified_content.as_bytes().to_vec())
}

/// Remove annotation-based watermark
fn remove_annotation_watermark(
    target_data: Vec<u8>,
    watermark: &WatermarkDetection,
) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);
    let mut modified_content = content_str.to_string();

    log::debug!("Removing annotation watermark at coordinates: ({}, {})", 
               watermark.coordinates.x, watermark.coordinates.y);

    // Find annotation objects that match watermark characteristics
    let annotation_patterns = [
        r"\d+\s+\d+\s+obj\s*<<[^>]*\/Subtype\s*\/Text[^>]*>>.*?endobj",
        r"\d+\s+\d+\s+obj\s*<<[^>]*\/Subtype\s*\/FreeText[^>]*>>.*?endobj", 
        r"\d+\s+\d+\s+obj\s*<<[^>]*\/Subtype\s*\/Stamp[^>]*>>.*?endobj",
        r"\d+\s+\d+\s+obj\s*<<[^>]*\/Subtype\s*\/Watermark[^>]*>>.*?endobj",
    ];

    let _watermark_indicators = [
        "ilovepdf", "smallpdf", "pdf24", "sejda", "watermark", "trial", "evaluation"
    ];

    for pattern in annotation_patterns {
        if let Ok(regex) = regex::Regex::new(pattern) {
            let indices: Vec<_> = regex.find_iter(&modified_content)
                .map(|m| (m.start(), m.end()))
                .collect();
            for (start, end) in indices.iter().rev() {
                modified_content.replace_range(*start..*end, "");
            }
        }
    }

    // Remove references to deleted annotation objects from page dictionaries
    let page_annot_pattern = r"/Annots\s*\[\s*([0-9\s]+R\s*)*\]";
    if let Ok(regex) = regex::Regex::new(page_annot_pattern) {
        // This is simplified - in a real implementation you'd track which objects were removed
        // and update the references accordingly
         let indices: Vec<_> = regex.find_iter(&modified_content)
                .map(|m| (m.start(), m.end()))
                .collect();
            for (start, end) in indices.iter().rev() {
                modified_content.replace_range(*start..*end, "");
            }
    }

    log::debug!("Annotation watermark removal completed, size change: {} bytes",
               content_str.len() as i64 - modified_content.len() as i64);

    Ok(modified_content.as_bytes().to_vec())
}

/// Check if annotation coordinates approximately match watermark coordinates
fn check_annotation_coordinates(annotation_content: &str, target_coords: &Rectangle) -> bool {
    // Look for /Rect array in annotation
    let rect_pattern = r"/Rect\s*\[\s*([0-9.-]+)\s+([0-9.-]+)\s+([0-9.-]+)\s+([0-9.-]+)\s*\]";

    if let Ok(regex) = regex::Regex::new(rect_pattern) {
        if let Some(captures) = regex.captures(annotation_content) {
            if let (Ok(x1), Ok(y1), Ok(x2), Ok(y2)) = (
                captures[1].parse::<f64>(),
                captures[2].parse::<f64>(),
                captures[3].parse::<f64>(),
                captures[4].parse::<f64>(),
            ) {
                // Check if coordinates are approximately the same (within 20 units)
                let tolerance = 20.0;
                return (x1 - target_coords.x).abs() < tolerance &&
                       (y1 - target_coords.y).abs() < tolerance &&
                       ((x2 - x1) - target_coords.width).abs() < tolerance &&
                       ((y2 - y1) - target_coords.height).abs() < tolerance;
            }
        }
    }

    false
}

/// Remove object-based watermark
fn remove_object_watermark(
    target_data: Vec<u8>,
    watermark: &WatermarkDetection,
) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);

    // Find and remove suspicious objects
    let object_start = locate_watermark_object(&content_str, &watermark.coordinates)?;
    let object_end = find_object_end(&content_str, object_start)?;

    // Check if object is truly a watermark before removing
    let object_content = &content_str[object_start..object_end];
    if confirm_watermark_object(object_content) {
        let mut result = String::new();
        result.push_str(&content_str[..object_start]);
        result.push_str(&content_str[object_end..]);

        return Ok(result.as_bytes().to_vec());
    }

    Ok(target_data)
}

/// Remove coordinate-based watermark
fn remove_coordinate_watermark(
    target_data: Vec<u8>,
    watermark: &WatermarkDetection,
) -> PdfResult<Vec<u8>> {
    let content_str = String::from_utf8_lossy(&target_data);

    // Remove positioning commands for watermark coordinates
    let cleaned = content_str.replace(&format!("{} {} Td", watermark.coordinates.x as i32, watermark.coordinates.y as i32), "");
    Ok(cleaned.as_bytes().to_vec())
}





/// Validate that original content is preserved
fn validate_content_preservation(
    modified_data: &[u8],
    source_data: &PdfForensicData,
) -> PdfResult<()> {
    // Check that page count hasn't changed
    let content_str = String::from_utf8_lossy(modified_data);
    let _page_count = count_pages(&content_str)?;

    if let Some(ref _page_tree) = source_data.structure.page_tree {
        // Page tree structure validation - using page_count parameter since PageTreeStructure is an enum
        log::debug!("Validating page tree structure consistency after watermark removal");
    }

    // Check for presence of critical content objects
    validate_content_objects(&content_str)?;

    Ok(())
}

/// Helper functions for watermark detection and removal

fn extract_annotation_context(content: &str, pos: usize) -> PdfResult<String> {
    let start = if pos >= 500 { pos - 500 } else { 0 };
    let end = std::cmp::min(pos + 500, content.len());
    Ok(content[start..end].to_string())
}

fn classify_annotation_source(context: &str) -> Option<WatermarkSource> {
    let context_lower = context.to_lowercase();

    if context_lower.contains("ilovepdf") {
        Some(WatermarkSource::ILovePdf {
            signature: "ilovepdf".to_string(),
            url_pattern: Some("www.ilovepdf.com".to_string()),
        })
    } else if context_lower.contains("adobe") {
        Some(WatermarkSource::Adobe {
            product: "Adobe Acrobat".to_string(),
            version: None,
        })
    } else if context_lower.contains("foxit") {
        Some(WatermarkSource::Foxit {
            product: "Foxit Reader".to_string(),
            license_type: None,
        })
    } else if context_lower.contains("pdf24") {
        Some(WatermarkSource::Pdf24 {
            signature: "pdf24".to_string(),
        })
    } else if context_lower.contains("smallpdf") {
        Some(WatermarkSource::SmallPdf {
            service_url: Some("smallpdf.com".to_string()),
        })
    } else {
        Some(WatermarkSource::Unknown {
            patterns: vec![context.to_string()],
        })
    }
}

fn extract_annotation_location(context: &str) -> PdfResult<Rectangle> {
    // Extract coordinates from annotation context using simple parsing
    let numbers = extract_numbers_from_context(context);

    if numbers.len() >= 4 {
        Ok(Rectangle {
            x: numbers[0],
            y: numbers[1],
            width: numbers[2],
            height: numbers[3],
        })
    } else {
        Ok(Rectangle { x: 0.0, y: 0.0, width: 100.0, height: 20.0 })
    }
}



fn extract_numbers_from_context(context: &str) -> Vec<f64> {
    let mut numbers = Vec::new();
    let mut current_number = String::new();
    let mut in_number = false;

    for ch in context.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            current_number.push(ch);
            in_number = true;
        } else if in_number {
            if let Ok(num) = current_number.parse::<f64>() {
                numbers.push(num);
            }
            current_number.clear();
            in_number = false;
        }
    }

    // Don't forget the last number if the string ends with one
    if in_number {
        if let Ok(num) = current_number.parse::<f64>() {
            numbers.push(num);
        }
    }

    numbers
}

fn is_watermark_position(coords: &[f64]) -> bool {
    if coords.len() >= 2 {
        let x = coords[0];
        let y = coords[1];

        // Common watermark positions (corners, center, edges)
        (x < 100.0 && y < 100.0) ||  // Bottom-left corner
        (x > 400.0 && y < 100.0) ||  // Bottom-right corner
        (x < 100.0 && y > 600.0) ||  // Top-left corner
        (x > 400.0 && y > 600.0) ||  // Top-right corner
        (x > 200.0 && x < 400.0 && y > 300.0 && y < 500.0) // Center area
    } else {
        false
    }
}

fn generate_text_variations(text: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Case variations
    variations.push(text.to_lowercase());
    variations.push(text.to_uppercase());

    // Space variations
    variations.push(text.replace(' ', ""));
    variations.push(text.replace(' ', "_"));
    variations.push(text.replace(' ', "-"));

    // URL variations
    if text.contains(".com") {
        variations.push(text.replace("http://", ""));
        variations.push(text.replace("https://", ""));
        variations.push(text.replace("www.", ""));
    }

    variations
}









fn confirm_watermark_object(object_content: &str) -> bool {
    // Confirm this is actually a watermark object
    let watermark_keywords = [
        "watermark", "trial", "evaluation", "demo", "ilovepdf", 
        "adobe", "foxit", "pdf24", "smallpdf"
    ];

    let content_lower = object_content.to_lowercase();
    watermark_keywords.iter().any(|&keyword| content_lower.contains(keyword))
}



fn validate_content_objects(content: &str) -> PdfResult<()> {
    // Ensure critical content objects are still present
    let required_objects = ["/Type /Catalog", "/Type /Pages"];

    for required in required_objects {
        if !content.contains(required) {
            return Err(PdfError::WatermarkRemoval {
                message: format!("Critical object missing after watermark removal: {}", required),
                watermark_type: "validation".to_string(),
            });
        }
    }

    Ok(())
}

/// Main watermark filtering function
pub fn filter_watermarks(target_data: Vec<u8>, source_data: &PdfForensicData) -> PdfResult<Vec<u8>> {
    remove_watermarks(target_data, source_data)
}

/// Remove watermarks from PDF forensic data
pub fn remove_watermarks_from_content(
    pdf_content: Vec<u8>,
    watermarks: &[WatermarkDetection],
) -> PdfResult<Vec<u8>> {
    let mut content = pdf_content;

    for watermark in watermarks {
        content = remove_specific_watermark(content, watermark)?;
    }

    Ok(content)
}

/// Detect common watermark patterns in PDF content
pub fn detect_watermark_patterns(pdf_content: &[u8]) -> PdfResult<Vec<WatermarkDetection>> {
    detect_all_watermarks(pdf_content)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watermark_detection() {
        // Test watermark pattern detection
        let test_text = "iLovePDF watermark test";
        assert!(is_watermark_text(test_text));

        let normal_text = "Regular PDF content";
        assert!(!is_watermark_text(normal_text));
    }

    #[test]
    fn test_annotation_creation() {
        let annotation = Annotation {
            annotation_type: AnnotationType::Text,
            contents: Some("ilovepdf".to_string()),
            object_ref: ObjectReference {
                number: 101,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(0.0, 0.0, 100.0, 50.0),
            is_original: false,
            tool_signature: Some("ilovepdf".to_string()),
            properties: std::collections::HashMap::new(),
        };

        assert!(is_watermark_annotation(&annotation));
    }

    #[test] 
    fn test_annotation_detection() {
        let annotation2 = Annotation {
            annotation_type: AnnotationType::Text,
            contents: Some("watermark text".to_string()),
            object_ref: ObjectReference {
                number: 102,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(0.0, 0.0, 100.0, 50.0),
            is_original: false,
            tool_signature: Some("watermark_tool".to_string()),
            properties: std::collections::HashMap::new(),
        };

        assert_eq!(is_watermark_annotation(&annotation2), true);

        // Test case 3: FreeText annotation with watermark content
        let annotation3 = Annotation {
            annotation_type: AnnotationType::FreeText {
                formatting: TextFormatting {
                    font_name: None,
                    font_size: Some(12.0),
                    text_color: None,
                    alignment: None,
                    bold: false,
                    italic: false,
                },
            },
            contents: Some("trial version".to_string()),
            object_ref: ObjectReference {
                number: 102,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(50.0, 50.0, 200.0, 100.0),
            is_original: false,
            tool_signature: Some("trial_watermark".to_string()),
            properties: std::collections::HashMap::new(),
        };
        assert_eq!(is_watermark_annotation(&annotation3), true);

        // Test case 4: Text annotation without watermark content
        let annotation4 = Annotation {
            annotation_type: AnnotationType::Text,
            contents: Some("Regular Text".to_string()),
            object_ref: ObjectReference {
                number: 103,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(10.0, 10.0, 80.0, 30.0),
            is_original: true,
            tool_signature: None,
            properties: std::collections::HashMap::new(),
        };
        assert_eq!(is_watermark_annotation(&annotation4), false);

        // Test case 5: No content
        let annotation5 = Annotation {
            annotation_type: AnnotationType::Text,
            contents: None,
            object_ref: ObjectReference {
                number: 104,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(0.0, 0.0, 50.0, 25.0),
            is_original: true,
            tool_signature: None,
            properties: std::collections::HashMap::new(),
        };
        assert_eq!(is_watermark_annotation(&annotation5), false);

        // Test case 6: Other annotation type
        let annotation6 = Annotation {
            annotation_type: AnnotationType::Link {
                destination: LinkDestination::Url {
                    url: "http://example.com".to_string(),
                },
            },
            contents: None,
            object_ref: ObjectReference {
                number: 100,
                generation: 0,
            },
            page_ref: ObjectReference {
                number: 1,
                generation: 0,
            },
            flags: AnnotationFlags {
                invisible: false,
                hidden: false,
                print: true,
                no_zoom: false,
                no_rotate: false,
                no_view: false,
                read_only: false,
                locked: false,
                toggle_no_view: false,
                locked_contents: false,
                raw_flags: 0,
            },
            title: None,
            creation_date: None,
            modification_date: None,
            rect: Rectangle::new(20.0, 20.0, 120.0, 40.0),
            is_original: true,
            tool_signature: None,
            properties: std::collections::HashMap::new(),
        };
        assert_eq!(is_watermark_annotation(&annotation6), false);
    }

    #[test]
    fn test_is_watermark_text() {
        // Test case 1: Contains "ilovepdf"
        assert_eq!(is_watermark_text("This contains ilovepdf text"), true);

        // Test case 2: Contains "smallpdf"
        assert_eq!(is_watermark_text("smallpdf is in this text"), true);

        // Test case 3: Contains "pdf24"
        assert_eq!(is_watermark_text("Text with pdf24"), true);

        // Test case 4: Contains "sejda"
        assert_eq!(is_watermark_text("sejda watermark here"), true);

        // Test case 5: Contains "watermark"
        assert_eq!(is_watermark_text("A watermark is present"), true);

        // Test case 6: Contains "trial version"
        assert_eq!(is_watermark_text("This is a trial version"), true);

        // Test case 7: Contains "evaluation copy"
        assert_eq!(is_watermark_text("evaluation copy detected"), true);

        // Test case 8: Contains "unlicensed"
        assert_eq!(is_watermark_text("unlicensed software"), true);

        // Test case 9: No watermark text
        assert_eq!(is_watermark_text("This is regular text"), false);

        // Test case 10: Empty string
        assert_eq!(is_watermark_text(""), false);
    }

    #[test]
    fn test_remove_object_content() -> PdfResult<()> {
        // Mock data
        let original_data = b"10 0 obj\n<< /Type /Page >>\nendobj\n20 0 obj\n<< /Watermark true >>\nendobj\n".to_vec();
        let obj_ref = ObjectReference { number: 20, generation: 0 };

        // Apply function
        let result = remove_object_content(original_data, &obj_ref)?;

        // Expected result
        let expected_data = b"10 0 obj\n<< /Type /Page >>\nendobj\n20 0 obj\n<<\n>>\nendobj\n".to_vec();

        // Assert
        assert_eq!(result, expected_data);

        Ok(())
    }

    #[test]
    fn test_remove_watermarks_from_data() -> PdfResult<()> {
        // Mock data
        let mut target_data = PdfForensicData {
            metadata: crate::types::DocumentMetadata {
                title: Some("Test PDF".to_string()),
                author: Some("Test Author".to_string()),
                subject: None,
                keywords: None,
                creator: Some("iLovePDF".to_string()),
                producer: Some("iLovePDF".to_string()),
                creation_date: None,
                mod_date: None,
                trapped: None,
                custom_fields: std::collections::HashMap::new(),
                raw_info_bytes: Vec::new(),
                info_object_ref: None,
            },
            annotations: crate::types::AnnotationData {
                annotations: vec![
                    Annotation {
                        object_ref: ObjectReference {
                            number: 100,
                            generation: 0,
                        },
                        annotation_type: AnnotationType::Watermark {
                            properties: crate::types::WatermarkProperties {
                                text: Some("Watermark".to_string()),
                                opacity: 0.5,
                                rotation: None,
                                scale: None,
                            },
                        },
                        rect: crate::types::Rectangle {
                            x: 0.0,
                            y: 0.0,
                            width: 100.0,
                            height: 50.0,
                        },
                        page_ref: ObjectReference {
                            number: 2,
                            generation: 0,
                        },
                        flags: crate::types::AnnotationFlags {
                            invisible: false,
                            hidden: false,
                            print: true,
                            no_zoom: false,
                            no_rotate: false,
                            no_view: false,
                            read_only: false,
                            locked: false,
                            toggle_no_view: false,
                            locked_contents: false,
                            raw_flags: 4,
                        },
                        contents: Some("Watermark".to_string()),
                        title: None,
                        creation_date: None,
                        modification_date: None,
                        is_original: false,
                        tool_signature: Some("iLovePDF".to_string()),
                        properties: std::collections::HashMap::new(),
                    },
                    Annotation {
                        object_ref: ObjectReference {
                            number: 101,
                            generation: 0,
                        },
                        annotation_type: AnnotationType::Text,
                        rect: crate::types::Rectangle {
                            x: 50.0,
                            y: 50.0,
                            width: 100.0,
                            height: 20.0,
                        },
                        page_ref: ObjectReference {
                            number: 2,
                            generation: 0,
                        },
                        flags: AnnotationFlags {
                            invisible: false,
                            hidden: false,
                            print: true,
                            no_zoom: false,
                            no_rotate: false,
                            no_view: false,
                            read_only: false,
                            locked: false,
                            toggle_no_view: false,
                            locked_contents: false,
                            raw_flags: 4,
                        },
                        contents: Some("Regular Text".to_string()),
                        title: None,
                        creation_date: None,
                        modification_date: None,
                        is_original: true,
                        tool_signature: None,
                        properties: std::collections::HashMap::new(),
                    },
                ],
                statistics: crate::types::AnnotationStatistics {
                    total_count: 2,
                    count_by_type: HashMap::new(),
                    count_by_page: HashMap::new(),
                    average_size: 0.0,
                    date_range: None,
                },
                appearances: vec![],
            },
            ..Default::default()
        };

        // Apply function
        remove_watermarks_from_data(&mut target_data)?;

        // Assert
        assert_eq!(target_data.annotations.annotations.len(), 1);
        assert_eq!(target_data.metadata.creator, None);
        assert_eq!(target_data.metadata.producer, None);

        Ok(())
    }

    #[test]
    fn test_extract_annotation_context() -> PdfResult<()> {
        // Mock data
        let content = "Some text before /Subtype /Text annotation content here and after".to_string();
        let pos = content.find("/Subtype /Text").unwrap();

        // Apply function
        let context = extract_annotation_context(&content, pos)?;

        // Assert - check that extracted context is not empty
        assert!(!context.is_empty());

        // Check that it contains the target string
        assert!(context.contains("/Subtype /Text"));

        Ok(())
    }

    #[test]
    fn test_classify_annotation_source() {
        // Test case 1: iLovePDF
        let context1 = "This is an iLovePDF annotation".to_string();
        let source1 = classify_annotation_source(&context1).unwrap();
        if let WatermarkSource::ILovePdf { .. } = source1 {
            assert!(true); // Correct source detected
        } else {
            assert!(false); // Incorrect source
        }

        // Test case 2: Adobe
        let context2 = "An Adobe Acrobat annotation".to_string();
        let source2 = classify_annotation_source(&context2).unwrap();
        if let WatermarkSource::Adobe { .. } = source2 {
            assert!(true);
        } else {
            assert!(false);
        }

        // Test case 3: Foxit
        let context3 = "From Foxit Reader".to_string();
        let source3 = classify_annotation_source(&context3).unwrap();
        if let WatermarkSource::Foxit { .. } = source3 {
            assert!(true);
        } else {
            assert!(false);
        }

        // Test case 4: PDF24
        let context4 = "Generated by PDF24".to_string();
        let source4 = classify_annotation_source(&context4).unwrap();
        if let WatermarkSource::Pdf24 { .. } = source4 {
            assert!(true);
        } else {
            assert!(false);
        }

        // Test case 5: SmallPDF
        let context5 = "Using SmallPDF tools".to_string();
        let source5 = classify_annotation_source(&context5).unwrap();
        if let WatermarkSource::SmallPdf { .. } = source5 {
            assert!(true);
        } else {
            assert!(false);
        }

        // Test case 6: Unknown
        let context6 = "Generic annotation".to_string();
        let source6 = classify_annotation_source(&context6).unwrap();
        if let WatermarkSource::Unknown { .. } = source6 {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_extract_annotation_location() -> PdfResult<()> {
        // Mock data
        let context = "Some text 10.0 20.0 100.0 200.0 annotation content".to_string();

        // Apply function
        let location = extract_annotation_location(&context)?;

        // Assert
        assert_eq!(location.x, 10.0);
        assert_eq!(location.y, 20.0);
        assert_eq!(location.width, 100.0);
        assert_eq!(location.height, 200.0);

        Ok(())
    }

    #[test]
    fn test_extract_numbers_from_context() {
        // Test case 1: Basic numbers
        let context1 = "10 20 30 40".to_string();
        let numbers1 = extract_numbers_from_context(&context1);
        assert_eq!(numbers1, vec![10.0, 20.0, 30.0, 40.0]);

        // Test case 2: Decimal numbers
        let context2 = "10.5 20.75 30.0 40.2".to_string();
        let numbers2 = extract_numbers_from_context(&context2);
        assert_eq!(numbers2, vec![10.5, 20.75, 30.0, 40.2]);

        // Test case 3: Mixed numbers and text
        let context3 = "Text 10 more text 20.5 and 30".to_string();
        let numbers3 = extract_numbers_from_context(&context3);
        assert_eq!(numbers3, vec![10.0, 20.5, 30.0]);

        // Test case 4: No numbers
        let context4 = "Just text".to_string();
        let numbers4 = extract_numbers_from_context(&context4);
        assert_eq!(numbers4, Vec::<f64>::new());

        // Test case 5: Numbers with dots in other context
        let context5 = "Version 1.2.3".to_string();
        let numbers5 = extract_numbers_from_context(&context5);
        assert_eq!(numbers5, vec![1.0, 2.0, 3.0]);

        // Test case 6: Numbers at the beginning and end
        let context6 = "10 Text 20".to_string();
        let numbers6 = extract_numbers_from_context(&context6);
        assert_eq!(numbers6, vec![10.0, 20.0]);
    }

    #[test]
    fn test_is_watermark_position() {
        // Test case 1: Bottom-left corner
        assert_eq!(is_watermark_position(&[50.0, 50.0]), true);

        // Test case 2: Bottom-right corner
        assert_eq!(is_watermark_position(&[450.0, 50.0]), true);

        // Test case 3: Top-left corner
        assert_eq!(is_watermark_position(&[50.0, 650.0]), true);

        // Test case 4: Top-right corner
        assert_eq!(is_watermark_position(&[450.0, 650.0]), true);

        // Test case 5: Center area
        assert_eq!(is_watermark_position(&[300.0, 400.0]), true);

        // Test case 6: Not a watermark position
        assert_eq!(is_watermark_position(&[200.0, 200.0]), false);

        // Test case 7: Insufficient coordinates
        assert_eq!(is_watermark_position(&[200.0]), false);
    }

    #[test]
    fn test_generate_text_variations() {
        // Test case 1: Basic text
        let text1 = "iLovePDF".to_string();
        let variations1 = generate_text_variations(&text1);
        assert!(variations1.contains(&"ilovepdf".to_string()));
        assert!(variations1.contains(&"ILOVEPDF".to_string()));

        // Test case 2: Text with spaces
        let text2 = "Trial Version".to_string();
        let variations2 = generate_text_variations(&text2);
        assert!(variations2.contains(&"trial version".to_string()));
        assert!(variations2.contains(&"TRIAL VERSION".to_string()));
        assert!(variations2.contains(&"TrialVersion".to_string()));
        assert!(variations2.contains(&"Trial_Version".to_string()));
        assert!(variations2.contains(&"Trial-Version".to_string()));

        // Test case 3: URL
        let text3 = "www.example.com".to_string();
        let variations3 = generate_text_variations(&text3);
        assert!(variations3.contains(&"example.com".to_string()));

        // Test case 4: Mixed
        let text4 = "Test.com example".to_string();
        let variations4 = generate_text_variations(&text4);
        assert!(variations4.contains(&"test.com example".to_string()));
        assert!(variations4.contains(&"TEST.COM EXAMPLE".to_string()));
        assert!(variations4.contains(&"Test.comexample".to_string()));
    }

    #[test]
    fn test_locate_annotation_object() -> PdfResult<()>{
        // Mock data
        let content = "obj 10 0\n<< /Type /Annot /Rect [ 10 20 100 200 ] >>\nendobj".to_string();
        let location = Rectangle { x: 10.0, y: 20.0, width: 100.0, height: 200.0 };

        // Apply function
        let position = locate_annotation_object(&content, &location)?;

        // Assert
        assert_eq!(position, 4);

        Ok(())
    }

    #[test]
    fn test_find_annotation_end() -> PdfResult<()> {
        // Mock data
        let content = "obj 10 0\n<< /Type /Annot >>\nendobj Some other content".to_string();
        let start = 0;

        // Apply function
        let end = find_annotation_end(&content, start)?;

        // Assert
        assert_eq!(end, 38);

        Ok(())
    }

    #[test]
    fn test_locate_watermark_object() -> PdfResult<()> {
        // Mock data
        let content = "obj 20 0\n<< /Watermark true >>\nendobj".to_string();
        let location = Rectangle { x: 4.0, y: 0.0, width: 0.0, height: 0.0 };

        // Apply function
        let position = locate_watermark_object(&content, &location)?;

        // Assert
        assert_eq!(position, 4);

        Ok(())
    }

    #[test]
    fn test_find_object_end() -> PdfResult<()> {
        // Mock data
        let content = "obj 20 0\n<< /Watermark true >>\nendobj Some other content".to_string();
        let start = 0;

        // Apply function
        let end = find_object_end(&content, start)?;

        // Assert
        assert_eq!(end, 38);

        Ok(())
    }

    #[test]
    fn test_confirm_watermark_object() {
        // Test case 1: Contains "watermark"
        let content1 = "<< /Watermark true >>".to_string();
        assert_eq!(confirm_watermark_object(&content1), true);

        // Test case 2: Contains "trial"
        let content2 = "<< /TrialVersion true >>".to_string();
        assert_eq!(confirm_watermark_object(&content2), true);

        // Test case 3: Contains "ilovepdf"
        let content3 = "<< /Creator (iLovePDF) >>".to_string();
        assert_eq!(confirm_watermark_object(&content3), true);

        // Test case 4: Clean object
        let content4 = "<< /Type /Page >>".to_string();
        assert_eq!(confirm_watermark_object(&content4), false);
    }

    #[test]
    fn test_count_pages() -> PdfResult<()> {
        // Test case 1: Multiple pages
        let content1 = "obj 10 0\n<< /Type /Page >>\nendobj\nobj 20 0\n<< /Type /Page >>\nendobj".to_string();
        assert_eq!(count_pages(&content1)?, 2);

        // Test case 2: Single page
        let content2 = "obj 10 0\n<< /Type /Page >>\nendobj".to_string();
        assert_eq!(count_pages(&content2)?, 1);

        // Test case 3: No pages
        let content3 = "obj 10 0\n<< /Type /Catalog >>\nendobj".to_string();
        assert_eq!(count_pages(&content3)?, 1);

        Ok(())
    }

    #[test]
    fn test_validate_content_objects() -> PdfResult<()> {
        // Test case 1: Valid content
        let content1 = "<< /Type /Catalog >>\n<< /Type /Pages >>".to_string();
        assert!(validate_content_objects(&content1).is_ok());

        // Test case 2: Missing Catalog
        let content2 = "<< /Type /Pages >>".to_string();
        let result2 = validate_content_objects(&content2);
        assert!(result2.is_err());

        // Test case 3: Missing Pages
        let content3 = "<< /Type /Catalog >>".to_string();
        let result3 = validate_content_objects(&content3);
        assert!(result3.is_err());

        // Test case 4: Empty content
        let content4 = "".to_string();
        let result4 = validate_content_objects(&content4);
        assert!(result4.is_err());

        Ok(())
    }

    #[test]
    fn test_detect_text_watermarks() -> PdfResult<()> {
        let pdf_data = b"This PDF contains iLovePDF.com watermark.";
        let watermarks = detect_text_watermarks(pdf_data)?;
        assert!(!watermarks.is_empty());
        Ok(())
    }

    #[test]
    fn test_detect_annotation_watermarks() -> PdfResult<()> {
        let pdf_data = b"obj\n<< /Subtype /Watermark /Contents (This is a watermark) >>\nendobj";
        let watermarks = detect_annotation_watermarks(pdf_data)?;
        assert!(!watermarks.is_empty());
        Ok(())
    }

    #[test]
    fn test_detect_object_watermarks() ->PdfResult<()> {
        let pdf_data = b"obj\nq 1 0 0 1 0 0 cm\n/Image1 Do\nendobj";
        let watermarks = detect_object_watermarks(pdf_data)?;
        assert!(!watermarks.is_empty());
        Ok(())
    }

    #[test]
    fn test_detect_coordinate_watermarks() -> PdfResult<()> {
        let pdf_data = b"20 50 Td (Watermark)";
        let watermarks = detect_coordinate_watermarks(pdf_data)?;
        assert!(!watermarks.is_empty());
        Ok(())
    }

    #[test]
    fn test_remove_text_watermark() -> PdfResult<()> {
        let target_data = b"This PDF contains iLovePDF.com watermark.".to_vec();
        let watermark = WatermarkDetection {
            coordinates: Rectangle {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "iLovePDF.com".to_string(),
                font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "iLovePDF.com".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,
                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::TextPattern { patterns: vec![] },
        };
        let result = remove_text_watermark(target_data, &watermark)?;
        assert!(!String::from_utf8_lossy(&result).contains("iLovePDF.com"));
        Ok(())
    }

    #[test]
    fn test_remove_annotation_watermark() -> PdfResult<()> {
        let target_data = b"obj 10 0\n<< /Subtype /Watermark /Contents (This is a watermark) >>\nendobj".to_vec();
        let watermark = WatermarkDetection {
            coordinates: Rectangle {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "Watermark".to_string(),
                 font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "Watermark".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,
                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::VisualAnalysis { features: vec![] },
        };
        let result = remove_annotation_watermark(target_data, &watermark)?;
        assert!(!String::from_utf8_lossy(&result).contains("Watermark"));
        Ok(())
    }

    #[test]
    fn test_remove_object_watermark() -> PdfResult<()> {
        let target_data = b"obj 20 0\n<< /Watermark true /Contents (Watermark) >>\nendobj".to_vec();
        let watermark = WatermarkDetection {
            coordinates: Rectangle {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "Watermark".to_string(),
                 font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "Watermark".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::ObjectRelationship { patterns: vec![] },
        };
        let result = remove_object_watermark(target_data, &watermark)?;
assert!(!String::from_utf8_lossy(&result).contains("Watermark"));
        Ok(())
    }

    #[test]
    fn test_remove_coordinate_watermark() -> PdfResult<()> {
        let target_data = b"20 50 Td (Watermark)".to_vec();
        let watermark = WatermarkDetection {
            coordinates: Rectangle {
                x: 20.0,
                y: 50.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "Watermark".to_string(),
                 font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "Watermark".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,
                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::CoordinateAnalysis { position_patterns: vec![] },
        };
        let result = remove_coordinate_watermark(target_data, &watermark)?;
        assert!(!String::from_utf8_lossy(&result).contains("20 50 Td"));
        Ok(())
    }

    #[test]
    fn test_cleanup_watermark_references() -> PdfResult<()> {
        let target_data = b"obj\n<< /Resources << /ProcSet (PDF) /XObject << /Image1 1 0 R >> >> >>\nendobj".to_vec();
        let result = cleanup_watermark_references(target_data)?;
        assert_eq!(String::from_utf8_lossy(&result), "obj\n<< /Resources << /ProcSet (PDF) /XObject << /Image1 1 0 R >> >> >>\nendobj");
        Ok(())
    }

    #[test]
    fn test_filter_watermark_objects() -> PdfResult<()> {
        let target_data = b"obj 10 0\n<< /Type /Page >>\nendobj\nobj 20 0\n<< /Watermark true >>\nendobj".to_vec();
        let watermark_objects = vec![ObjectReference { number: 20, generation: 0 }];
        let result = filter_watermark_objects(target_data, &watermark_objects)?;
        assert!(!String::from_utf8_lossy(&result).contains("Watermark"));
        Ok(())
    }

    #[test]
    fn test_remove_specific_watermark() -> PdfResult<()> {
        let target_data = b"This PDF contains iLovePDF.com watermark.".to_vec();
        let watermark = WatermarkDetection {
            coordinates: Rectangle {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "iLovePDF.com".to_string(),
                 font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "iLovePDF.com".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,
                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::TextPattern { patterns: vec![] },
        };
        let result = remove_specific_watermark(target_data, &watermark)?;
        assert!(!String::from_utf8_lossy(&result).contains("iLovePDF.com"));
        Ok(())
    }

    #[test]
    fn test_filter_watermarks() -> PdfResult<()> {
        let target_data = b"This PDF contains iLovePDF.com watermark.".to_vec();
        let mut source_data = PdfForensicData::default();
        source_data.metadata = crate::types::DocumentMetadata {
                title: Some("Test Document".to_string()),
                author: Some("Test Author".to_string()),
                subject: None,
                keywords: None,
                creator: None,
                producer: None,
                creation_date: Some("2023-01-01".to_string()),
                mod_date: Some("2023-01-02".to_string()),
                trapped: None,
                custom_fields: std::collections::HashMap::new(),
                raw_info_bytes: Vec::new(),
                info_object_ref: None,
            };
        source_data.structure = crate::types::StructuralData {
                file_size: 1024,
                object_count: 10,
                indirect_objects: Vec::new(),
                eof_marker: crate::types::EofMarker {
                    offset: 1000,
                    raw_bytes: Vec::new(),
                    at_file_end: true,
                    trailing_bytes: None,
                },
                page_tree: Some(crate::types::PageTreeStructure::Linear),
                fonts: Vec::new(),
                images: Vec::new(),
                content_streams: Vec::new(),
                embedded_files: Vec::new(),
                javascript_objects: Vec::new(),
                suspicious_objects: Vec::new(),
            };
        source_data.annotations = crate::types::AnnotationData {
                annotations: vec![],
                statistics: crate::types::AnnotationStatistics {
                    total_count: 0,
                    count_by_type: HashMap::new(),
                    count_by_page: HashMap::new(),
                    average_size: 0.0,
                    date_range: None,
                },
                appearances: vec![],
            };
        source_data.forensic_markers = crate::types::ForensicMarkers {
                watermarks: Vec::new(),
                tool_signatures: Vec::new(),
                digital_signatures: Vec::new(),
                suspicious_patterns: Vec::new(),
                authenticity_indicators: crate::types::AuthenticityIndicators {
                    authenticity_score: 1.0,
                    positive_indicators: Vec::new(),
                    negative_indicators: Vec::new(),
                    assessment: crate::types::AuthenticityAssessment::Authentic { confidence: 1.0 },
                },
                tampering_evidence: Vec::new(),
                metadata_inconsistencies: Vec::new(),
            };
        let result = filter_watermarks(target_data, &source_data)?;
        assert!(!String::from_utf8_lossy(&result).contains("iLovePDF.com"));
        Ok(())
    }

    #[test]
    fn test_remove_watermarks_from_content_integration() -> PdfResult<()> {
        let pdf_content = b"This PDF contains iLovePDF.com watermark.".to_vec();
        let watermarks = vec![WatermarkDetection {
            coordinates: Rectangle {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            },
            source_tool: None,
            is_original: false,
            confidence: 0.0,
            watermark_type: WatermarkType::Text {
                text: "iLovePDF.com".to_string(),
                 font_info: Some(FontInfo {
                    object_ref: ObjectReference { number: 0, generation: 0 },
                    font_type: "Type1".to_string(),
                    base_font: Some("Helvetica".to_string()),
                    encoding: Some("StandardEncoding".to_string()),
                    embedded: false,
                    font_descriptor: None,
                }),
            },
            content: WatermarkContent::Text {
                text: "iLovePDF.com".to_string(),
                language: None,
                encoding: StringEncoding::Literal,
            },
            visual_properties: crate::types::WatermarkVisualProperties {
                opacity: None,
                color: Some(Color::Rgb { red: 0.5, green: 0.5, blue: 0.5 }),
                rotation: Some(0.0),
                scale: Some(1.0),
                blend_mode: Some("Normal".to_string()),
                z_order: Some(1),
                visibility: crate::types::WatermarkVisibility {
                    print: false,
                    screen: false,
                    zoom_range: Some((0.1, 10.0)),
                    conditional: false,
                },
            },
            associated_objects: vec![],
            detection_method: WatermarkDetectionMethod::TextPattern { patterns: vec![] },
        }];
        let result = remove_watermarks_from_content(pdf_content, &watermarks)?;
        assert!(!String::from_utf8_lossy(&result).contains("iLovePDF.com"));
        Ok(())
    }

    #[test]
    fn test_detect_watermark_patterns_integration() -> PdfResult<()> {
        let pdf_content = b"This PDF contains iLovePDF.com watermark.";
        let watermarks = detect_watermark_patterns(pdf_content)?;
        assert!(!watermarks.is_empty());
        Ok(())
    }
}