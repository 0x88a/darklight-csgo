#include "../gui.h"

void GUI::CONTROLS::BeginGroupbox(const std::string& szName, const int iHeight, const int iColumn)
{
	if (!m_bInitialized)
		return;

	m_iColumn = iColumn;

	m_iOldGroupboxHeight = iHeight;

	m_vOldGroupboxPos.x = m_iColumn ? D::ScaleDPI(218) : D::ScaleDPI(6);

	m_vOffset.x = m_vPos.x + D::ScaleDPI(15) + m_vOldGroupboxPos.x;
	m_vOffset.y = m_vPos.y + m_vOldGroupboxPos.y + D::ScaleDPI(16);

	m_szGroupboxName = szName;

	auto flOffsetFromLeft = m_vPos.x + D::ScaleDPI(6);
	auto flOffsetFromTop = m_vPos.y + m_vOldGroupboxPos.y - D::ScaleDPI(3);

	D::Rect(flOffsetFromLeft + m_vOldGroupboxPos.x - D::ScaleDPI(1),
		flOffsetFromTop - D::ScaleDPI(1),
		D::ScaleDPI(206), iHeight, Color(25, 25, 25, CONTROLS::m_flMenuAlpha));

	D::OutlinedRect(flOffsetFromLeft + m_vOldGroupboxPos.x - D::ScaleDPI(1),
		flOffsetFromTop - D::ScaleDPI(1),
		D::ScaleDPI(206),
		iHeight + D::ScaleDPI(2),
		Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	D::OutlinedRect(flOffsetFromLeft + m_vOldGroupboxPos.x,
		flOffsetFromTop,
		D::ScaleDPI(204),
		iHeight,
		Color(50, 50, 50, CONTROLS::m_flMenuAlpha));

	D::String(flOffsetFromLeft + m_vOldGroupboxPos.x + D::ScaleDPI(12),
		flOffsetFromTop + 2,
		D::uMenuFont[G::iDPIScale], m_szGroupboxName.c_str(),
		false,
		Color(205, 205, 205, CONTROLS::m_flMenuAlpha));

	groupboxTexture.Draw(flOffsetFromLeft + m_vOldGroupboxPos.x + D::ScaleDPI(77), flOffsetFromTop + 5, Color(255, 255, 255, CONTROLS::m_flMenuAlpha));
}
void GUI::CONTROLS::EndGroupbox()
{
	if (!m_bInitialized)
		return;

	m_vOldGroupboxPos.y += (m_vPos.y + m_iOldGroupboxHeight) - ((m_vPos.y + m_vOldGroupboxPos.y - D::ScaleDPI(3)) + D::ScaleDPI(16)) + D::ScaleDPI(75);
}